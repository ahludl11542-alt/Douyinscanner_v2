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
        root.addView(scroll, LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f)
        setContentView(root)
    }

    private fun mkButton(text: String, action: () -> Unit) = Button(this).apply {
        this.text = text
        setOnClickListener { action() }
    }

    private fun log(s: String) { runOnUiThread { output.append("$s\n") } }

    private fun scan() {
        output.text = ""
        candidates.clear()
        CoroutineScope(Dispatchers.IO).launch {
            val id = MemScan.su("id").trim()
            log("root: $id")
            if (!id.contains("uid=0")) { log("未获得 root"); return@launch }
            
            val ps = MemScan.su("ps -A")
            val procs = ps.lines().filter { it.contains("aweme", true) }
            if (procs.isEmpty()) { log("未找到抖音进程"); return@launch }

            for (line in procs) {
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.isEmpty()) continue
                val pidVal = parts[0].toLongOrNull() ?: continue
                
                val maps = MemScan.su("cat /proc/$pidVal/maps")
                val cand = mutableListOf<MapEntry>()
                for (ml in maps.lines()) {
                    val e = MapEntry.parse(pidVal, ml) ?: continue
                    if (e.isBigRwAnon()) cand.add(e)
                }
                cand.sortByDescending { it.size }
                log("PID $pidVal 候选 ${cand.size} 个")
                for (e in cand.take(10)) log(e.toString())
                candidates.addAll(cand)
            }
            log("扫描完成，共 ${candidates.size} 个候选")
        }
    }

    private fun scanCoords() {
        if (candidates.isEmpty()) { log("请先扫描进程"); return }
        val targets = candidates.sortedByDescending { it.size }.take(3)
        CoroutineScope(Dispatchers.IO).launch {
            for (t in targets) {
                val bytes = MemScan.readMem(t.pid, t.start, 4 * 1024 * 1024)
                if (bytes == null) { log("读取失败"); continue }
                log("== 坐标扫描 区域0x${t.start.toString(16)} ==")
                for (stride in intArrayOf(12, 16, 64)) {
                    val runs = MemScan.findVec3Runs(bytes, t.start, stride, 4, 5)
                    for (r in runs) log("stride=$stride 地址0x${r.first.toString(16)}")
                }
            }
            log("坐标扫描完成")
        }
    }

    private fun scanMatrices() {
        if (candidates.isEmpty()) { log("请先扫描进程"); return }
        val targets = candidates.sortedByDescending { it.size }.take(3)
        CoroutineScope(Dispatchers.IO).launch {
            for (t in targets) {
                val bytes = MemScan.readMem(t.pid, t.start, 4 * 1024 * 1024)
                if (bytes == null) { log("读取失败"); continue }
                log("== 矩阵扫描 区域0x${t.start.toString(16)} ==")
                val hits = MemScan.findMatrixCandidates(bytes, t.start, 20)
                for (h in hits) log("矩阵候选 0x${h.toString(16)}")
            }
            log("矩阵扫描完成")
        }
    } 
        
    private fun dumpFirst() {
        val e = candidates.maxByOrNull { it.size } ?: run { log("请先扫描进程"); return }
        CoroutineScope(Dispatchers.IO).launch {
            val bytes = MemScan.readMem(e.pid, e.start, 512)
            if (bytes == null || bytes.isEmpty()) { log("读取失败"); return@launch }
            log("== Hexdump 0x${e.start.toString(16)} ==")
            for (i in bytes.indices step 16) {
                val sb = StringBuilder()
                sb.append("%08x  ".format(e.start + i))
                for (j in 0 until 16) {
                    if (i + j < bytes.size) sb.append("%02x ".format(bytes[i + j].toInt() and 0xFF))
                    else sb.append("   ")
                    if (j == 7) sb.append(" ")
                }
                sb.append(" |")
                for (j in 0 until 16) {
                    if (i + j < bytes.size) {
                        val b = bytes[i + j].toInt() and 0xFF
                        sb.append(if (b in 32..126) b.toChar() else '.')
                    }
                }
                sb.append("|")
                log(sb.toString())
            }
        }
    }
}
