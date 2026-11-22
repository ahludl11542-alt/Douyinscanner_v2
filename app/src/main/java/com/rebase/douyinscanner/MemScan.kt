package com.rebase.douyinscanner

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.abs

object MemScan {

    fun su(cmd: String): String = try {
        val p = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
        val out = p.inputStream.bufferedReader().readText()
        val err = p.errorStream.bufferedReader().readText()
        p.waitFor()
        if (err.isNotBlank()) "ERR: $err" else out
    } catch (e: Exception) {
        "EXC: ${e.message}"
    }

    fun readMem(pid: Long, start: Long, size: Int): ByteArray? {
        if (size <= 0) return null
        val alignedStart = start and -4096L
        val offset = (start - alignedStart).toInt()
        val readSize = size + offset
        val blocks = (readSize + 4095) / 4096
        val path = "/data/local/tmp/rb_${pid}_${alignedStart}.bin"
        su("dd if=/proc/$pid/mem of=$path bs=4096 count=$blocks skip=${alignedStart / 4096} 2>/dev/null")
        val f = File(path)
        if (!f.exists() || f.length() == 0L) { f.delete(); return null }
        val raw = f.readBytes()
        f.delete()
        if (raw.size <= offset) return null
        val end = minOf(raw.size, offset + size)
        return raw.copyOfRange(offset, end)
    }

    private fun plausible(v: Float): Boolean = v.isFinite() && abs(v) < 20000f

    private fun plausibleVec(x: Float, y: Float, z: Float): Boolean =
        plausible(x) && plausible(y) && plausible(z) &&
        (abs(x) > 0.01f || abs(y) > 0.01f || abs(z) > 0.01f)

    fun findVec3Runs(
        bytes: ByteArray, baseAddr: Long, stride: Int,
        minRun: Int, maxHits: Int
    ): List<Pair<Long, Int>> {
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val hits = mutableListOf<Pair<Long, Int>>()
        var i = 0
        while (i + stride * minRun <= bytes.size && hits.size < maxHits) {
            var count = 0
            var j = i
            while (j + 12 <= bytes.size && count < 128) {
                val x = bb.getFloat(j)
                val y = bb.getFloat(j + 4)
                val z = bb.getFloat(j + 8)
                if (!plausibleVec(x, y, z)) break
                count++
                j += stride
            }
            if (count >= minRun) {
                hits.add(baseAddr + i to count)
                i += stride * count
            } else {
                i += 4
            }
        }
        return hits
    }

    fun findMatrixCandidates(bytes: ByteArray, baseAddr: Long, maxHits: Int): List<Long> {
        val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val hits = mutableListOf<Long>()
        var i = 0
        while (i + 64 <= bytes.size && hits.size < maxHits) {
            if (looksLikeMatrix(bb, i)) hits.add(baseAddr + i)
            i += 4
        }
        return hits
    }

    private fun looksLikeMatrix(bb: ByteBuffer, off: Int): Boolean {
        var small = 0
        for (k in 0 until 16) {
            val v = bb.getFloat(off + k * 4)
            if (!v.isFinite() || abs(v) > 100000f) return false
            if (abs(v) < 1.5f) small++
        }
        return small >= 3
    }
}
