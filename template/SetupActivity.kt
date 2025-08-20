package com.mikrotik.manager

import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.webkit.URLUtil
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen

class SetupActivity : AppCompatActivity() {

    private lateinit var urlInput: EditText
    private lateinit var saveButton: Button
    private lateinit var preferences: SharedPreferences

    override fun onCreate(savedInstanceState: Bundle?) {
        // Install splash screen with fast dismiss
        val splashScreen = installSplashScreen()
        splashScreen.setKeepOnScreenCondition { false }
        
        super.onCreate(savedInstanceState)

        try {
            // Initialize SharedPreferences first
            preferences = getSharedPreferences("mikrotik_settings", MODE_PRIVATE)
            
            // Check if already configured - if so, go directly to MainActivity
            if (isAppConfigured()) {
                goToMainActivity("")
                return
            }

            setContentView(R.layout.activity_setup)

            // Modern fullscreen for Android 15
            enableFullscreen()

            // Initialize views
            urlInput = findViewById(R.id.etServerUrl)
            saveButton = findViewById(R.id.btnSave)

            // Set click listener
            saveButton.setOnClickListener {
                val url = urlInput.text.toString().trim()
                if (validateUrl(url)) {
                    saveConfiguration(url)
                    goToMainActivity(url)
                } else {
                    Toast.makeText(this, "Please enter a valid URL (e.g., http://192.168.1.100:5000)", 
                        Toast.LENGTH_LONG).show()
                }
            }
        } catch (e: Exception) {
            Log.e("SetupActivity", "Error in onCreate", e)
            Toast.makeText(this, "Error starting setup: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    private fun enableFullscreen() {
        // Hide action bar
        supportActionBar?.hide()
        
        // Modern fullscreen for Android 11+ (API 30+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false)
            val controller = window.insetsController
            if (controller != null) {
                controller.hide(WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars())
                controller.systemBarsBehavior = WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
            }
        } else {
            // Fallback for older Android versions
            window.decorView.systemUiVisibility = (
                View.SYSTEM_UI_FLAG_FULLSCREEN or
                View.SYSTEM_UI_FLAG_HIDE_NAVIGATION or
                View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION or
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
            )
        }
    }

    private fun isAppConfigured(): Boolean {
        return try {
            preferences.getBoolean("is_configured", false) &&
                   !preferences.getString("server_url", "").isNullOrEmpty()
        } catch (e: Exception) {
            Log.e("SetupActivity", "Error checking configuration", e)
            false
        }
    }

    private fun validateUrl(url: String): Boolean {
        if (url.isEmpty()) return false
        
        val normalizedUrl = if (!url.startsWith("http://") && !url.startsWith("https://")) {
            "http://$url"
        } else {
            url
        }
        
        return URLUtil.isValidUrl(normalizedUrl)
    }

    private fun saveConfiguration(url: String) {
        try {
            val normalizedUrl = if (!url.startsWith("http://") && !url.startsWith("https://")) {
                "http://$url"
            } else {
                url
            }
            
            preferences.edit()
                .putString("server_url", normalizedUrl)
                .putBoolean("is_configured", true)
                .apply()
                
            Log.d("SetupActivity", "Configuration saved: $normalizedUrl")
        } catch (e: Exception) {
            Log.e("SetupActivity", "Error saving configuration", e)
            Toast.makeText(this, "Error saving configuration: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun goToMainActivity(url: String) {
        try {
            val intent = Intent(this, MainActivity::class.java)
            if (url.isNotEmpty()) {
                intent.putExtra("server_url", url)
            }
            startActivity(intent)
            finish()
        } catch (e: Exception) {
            Log.e("SetupActivity", "Error starting MainActivity", e)
            Toast.makeText(this, "Error starting main app: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onBackPressed() {
        // Prevent going back - user must configure the app
        Toast.makeText(this, "Please configure the server URL to continue", Toast.LENGTH_SHORT).show()
    }
}
