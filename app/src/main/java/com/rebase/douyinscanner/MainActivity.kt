package com.rebase.douyinscanner

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL

        val btn = Button(this)
        btn.text = "测试环境"
        btn.setOnClickListener {
            val res = MemScan.su("id")
            findViewById<TextView>(1).text = res
        }

        val text = TextView(this)
        text.id = 1
        text.text = "等待测试..."
        text.textSize = 16f

        root.addView(btn)
        root.addView(text)
        setContentView(root)
    }
}
