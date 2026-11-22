package com.rebase.douyinscanner

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File

class MainActivity : AppCompatActivity() {
    private lateinit var output: TextView
    private val candidates = mutableListOf<MapEntry>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val row1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val row2 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }

        row1.addView(mkButton("扫描进程/内存") { scan() })
        row1.addView(mkButton("Hexdump最大") { dumpFirst() })
        row2.addView(mkButton("扫坐标候选") { scanCoords() })
        row2.addView(mkButton("扫矩阵候选") { scanMatrices() })

        output = TextView(this).apply {
            textSize = 10f
            setTextIsSelectable(true)
            setPadding(16, 16, 16, 16)
        }
        val scroll = ScrollView(this).apply { addView(output) }
        root.addView(row1)
        root.addView(row2)
        root.addView(scroll, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
    }

    private fun mkButton(text: String, action: () -> Unit) = Button(this).apply {
        this.text = text
        setOnClickListener { action() }
    }

    private fun log(s: String) { runOnUiThread { output.append(s + "\n") } }

    private fun scan() {
        output.text = ""
        candidates.clear()
        CoroutineScope(Dispatchers.IO).launch {
            val id = MemScan.su("id").trim()
            log("root 检查: $id")
            if (!id.contains("uid=0")) {
                log("未获得 root，无法读取其它应用的 /proc。")
                return@launch
            }
            val ps = MemScan.su("ps -A")
            val procs = ps.lines().filter { it.contains("aweme", ignoreCase = true) }
            if (procs.isEmpty()) {
                log("未找到抖音进程。请先启动抖音并进入小游戏，再点扫描。")
                return@launch
            }
            for (line in procs) {
                val pid = line.trim().split(Regex("\\s+")).getOrNull(0)?.toLongOrNull() ?: continue
                val maps = MemScan.su("cat /proc/$pid/maps")
                val cand = mutableListOf<MapEntry>()
                for (ml in maps.lines()) {
                    val e = MapEntry.parse(pid, ml) ?: continue
                    if (e.isBigRwAnon()) cand.add(e)
                }
                cand.sortByDescending { it.size }
                log("\n== PID $pid  候选 ${cand.size} 个 ==")
                for (e in cand.take(30)) log(e.toString())
                candidates.addAll(cand)
            }
            log("\n扫描完成。共 ${candidates.size} 个候选。")
        }
    }

    private fun scanCoords() {
        if (candidates.isEmpty()) { log("先扫描进程/内存。"); return }
        val targets = candidates.sortedByDescending { it.size }.take(5)
        CoroutineScope(Dispatchers.IO).launch {
            for (t in targets) {
                val size = minOf(t.size, 8L * 1024 * 1024).toInt()
                val bytes = MemScan.readMem(t.pid, t.start, size)
                if (bytes == null) {
                    log("\n坐标扫描: 读取失败 pid=${t.pid} 0x${t.start.toString(16)}")
                    continue
                }
                log("\n== 坐标候选 pid=${t.pid} 区域0x${t.start.toString(16)} 读取${bytes.size}B ==")
                var any = false
                for (stride in intArrayOf(12, 16, 64)) {
                    val runs = MemScan.findVec3Runs(bytes, t.start, stride, 4, 5)
                    for ((addr, count) in runs) {
                        any = true
                        log("stride=$stride 起始0x${addr.toString(16)} 连续Vec3=$count")
                    }
                }
                if (!any) log("未发现连续 Vec3 候选。")
            }
            log("\n坐标扫描结束。以上均为启发式候选，未验证。")
        }
    }

    private fun scanMatrices() {
        if (candidates.isEmpty()) { log("先扫描进程/内存。"); return }
        val targets = candidates.sortedByDescending { it.size }.take(5)
        CoroutineScope(Dispatchers.IO).launch {
            for (t in targets) {
                val size = minOf(t.size, 8L * 1024 * 1024).toInt()
                val bytes = MemScan.readMem(t.pid, t.start, size)
                if (bytes == null) {
                    log("\n矩阵扫描: 读取失败 pid=${t.pid} 0x${t.start.toString(16)}")
                    continue
                }
                log("\n== 矩阵候选 pid=${t.pid} 区域0x${t.start.toString(16)} 读取${bytes.size}B ==")
                val hits = MemScan.findMatrixCandidates(bytes, t.start, 20)
                if (hits.isEmpty()) log("未发现矩阵候选。")
                for (h in hits) log("矩阵候选 0x$
