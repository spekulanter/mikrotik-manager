package com.mikrotik.manager

import android.annotation.SuppressLint
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import android.webkit.CookieManager
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebSettings
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.ViewCompat
import android.view.ViewGroup
import android.animation.ValueAnimator
import android.animation.ArgbEvaluator
import android.graphics.drawable.ColorDrawable

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var preferences: SharedPreferences

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            // Initialize SharedPreferences
            preferences = getSharedPreferences("mikrotik_settings", MODE_PRIVATE)

            // Check if app is configured
            if (!isAppConfigured()) {
                // Start setup activity for first-time configuration
                startActivity(Intent(this, SetupActivity::class.java))
                finish()
                return
            }

            // App is configured, proceed with normal startup
            initializeWebView()
        } catch (e: Exception) {
            Log.e("MainActivity", "Error in onCreate", e)
            Toast.makeText(this, "Error starting app: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    private fun isAppConfigured(): Boolean {
        return try {
            preferences.getBoolean("is_configured", false) &&
                   !preferences.getString("server_url", "").isNullOrEmpty()
        } catch (e: Exception) {
            Log.e("MainActivity", "Error checking configuration", e)
            false
        }
    }

    private fun initializeWebView() {
        try {
            setContentView(R.layout.activity_main)

            // Solid status bar with theme colors
            enableFullscreen()

            webView = findViewById(R.id.webView)

            // Remove overlay since we're using solid status bar
            // statusBarOverlay removed from layout and logic

            // Configure WebView settings
            with(webView.settings) {
                javaScriptEnabled = true
                domStorageEnabled = true
                databaseEnabled = true
                cacheMode = WebSettings.LOAD_DEFAULT
                allowFileAccess = false
                allowContentAccess = false
                setSupportZoom(false)
                builtInZoomControls = false
                displayZoomControls = false
                useWideViewPort = true
                loadWithOverviewMode = true
                javaScriptCanOpenWindowsAutomatically = false
                mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
                allowUniversalAccessFromFileURLs = false
                allowFileAccessFromFileURLs = false
                mediaPlaybackRequiresUserGesture = false
            }
            webView.overScrollMode = View.OVER_SCROLL_NEVER

            // Add JavaScript interface for theme-based status bar colors
            webView.addJavascriptInterface(object {
                @android.webkit.JavascriptInterface
                fun setStatusBarColor(color: String) {
                    runOnUiThread {
                        try {
                            val parsed = parseAnyColor(color)
                            window.statusBarColor = parsed
                            Log.d("StatusBar", "Status bar color set to: ${Integer.toHexString(parsed)}")
                        } catch (e: Exception) {
                            Log.e("MainActivity", "Error setting status bar color: $color", e)
                        }
                    }
                }
                
                @android.webkit.JavascriptInterface
                fun setStatusBarIcons(mode: String) {
                    runOnUiThread {
                        try {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                val controller = window.insetsController
                                if (controller != null) {
                                    if (mode == "dark") {
                                        // Dark icons for light background
                                        controller.setSystemBarsAppearance(
                                            WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS,
                                            WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                                        )
                                    } else {
                                        // Light icons for dark background
                                        controller.setSystemBarsAppearance(
                                            0,
                                            WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                                        )
                                    }
                                }
                            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                if (mode == "dark") {
                                    // Dark icons for light background
                                    window.decorView.systemUiVisibility = 
                                        window.decorView.systemUiVisibility or View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
                                } else {
                                    // Light icons for dark background
                                    window.decorView.systemUiVisibility = 
                                        window.decorView.systemUiVisibility and View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR.inv()
                                }
                            }
                        } catch (e: Exception) {
                            Log.e("MainActivity", "Error setting status bar icons: $mode", e)
                        }
                    }
                }
            }, "Android")

            // Enable cookies with persistence
            val cookieManager = CookieManager.getInstance()
            cookieManager.setAcceptCookie(true)
            cookieManager.setAcceptThirdPartyCookies(webView, true)
            
            // Force cookie persistence on Android 5.1+
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                cookieManager.flush()
            }

            // Custom WebViewClient for theme-based status bar
            webView.webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    // Force cookie sync after each page load
                    val cookieManager = CookieManager.getInstance()
                    cookieManager.flush()
                    Log.d("MainActivity", "Page loaded: $url, cookies synced")
                    
                    // Inject JavaScript for theme-based status bar colors
                    val js = """
                        (function() {
                            // Theme helpers
                            function getCurrentTheme() {
                                return document.body.classList.contains('light-theme') ? 'light' : 'dark';
                            }

                            // Update status bar based on theme
                            function updateStatusBar() {
                                const theme = getCurrentTheme();
                                if (theme === 'light') {
                                    // Light theme: light background, dark icons
                                    Android.setStatusBarColor('#f9fafb'); // Light gray
                                    Android.setStatusBarIcons('dark');
                                } else {
                                    // Dark theme: dark background, light icons
                                    Android.setStatusBarColor('#111827'); // Dark gray
                                    Android.setStatusBarIcons('light');
                                }
                            }

                            // Listen to theme changes
                            const observer = new MutationObserver(function(mutations) {
                                for (const m of mutations) {
                                    if (m.type === 'attributes' && m.attributeName === 'class') {
                                        setTimeout(updateStatusBar, 50);
                                    }
                                }
                            });
                            observer.observe(document.body, { attributes: true, attributeFilter: ['class'] });

                            // Initial call
                            setTimeout(updateStatusBar, 50);
                        })();
                    """
                    
                    view?.evaluateJavascript(js, null)
                }
            }

            // Load saved server URL
            val serverUrl = getServerUrl()
            if (serverUrl.isNotEmpty()) {
                Log.d("MainActivity", "Loading URL: $serverUrl")
                webView.loadUrl(serverUrl)
            } else {
                Toast.makeText(this, "No server URL configured", Toast.LENGTH_LONG).show()
                startActivity(Intent(this, SetupActivity::class.java))
                finish()
            }
        } catch (e: Exception) {
            Log.e("MainActivity", "Error initializing WebView", e)
            Toast.makeText(this, "Error loading WebView: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    private fun getServerUrl(): String {
        return try {
            // Try to get URL from intent first (from SetupActivity)
            val intentUrl = intent.getStringExtra("server_url")
            if (!intentUrl.isNullOrEmpty()) {
                return intentUrl
            }

            // Otherwise get from SharedPreferences
            preferences.getString("server_url", "") ?: ""
        } catch (e: Exception) {
            Log.e("MainActivity", "Error getting server URL", e)
            ""
        }
    }

    private fun enableFullscreen() {
        try {
            // Hide action bar
            supportActionBar?.hide()
            
            // Solid status bar with theme-based colors
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS)
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS)

            // Default dark theme colors
            window.statusBarColor = android.graphics.Color.parseColor("#111827") // Dark theme
            window.navigationBarColor = android.graphics.Color.parseColor("#111827")

            // Normal layout - let system handle status bar space automatically
            WindowCompat.setDecorFitsSystemWindows(window, true)

            // Light icons for dark background (will be updated by JS based on theme)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                window.insetsController?.setSystemBarsAppearance(
                    0, // Light icons
                    WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                )
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                window.decorView.systemUiVisibility = 
                    window.decorView.systemUiVisibility and View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR.inv()
            }
        } catch (e: Exception) {
            Log.e("MainActivity", "Error enabling fullscreen", e)
        }
    }

    // Parse color strings: rgba(r,g,b,a), #RRGGBB, #RRGGBBAA, or #00000000 for transparent
    private fun parseAnyColor(color: String): Int {
        return try {
            if (color.equals("#00000000", ignoreCase = true)) {
                android.graphics.Color.TRANSPARENT
            } else if (color.startsWith("rgba")) {
                val rgba = color.removePrefix("rgba(").removeSuffix(")").split(",")
                if (rgba.size == 4) {
                    val r = rgba[0].trim().toInt()
                    val g = rgba[1].trim().toInt()
                    val b = rgba[2].trim().toInt()
                    val a = (rgba[3].trim().toFloat() * 255).toInt()
                    android.graphics.Color.argb(a, r, g, b)
                } else {
                    android.graphics.Color.TRANSPARENT
                }
            } else if (color.startsWith("#") && color.length == 9) {
                val hex = color.removePrefix("#")
                val r = hex.substring(0, 2).toInt(16)
                val g = hex.substring(2, 4).toInt(16)
                val b = hex.substring(4, 6).toInt(16)
                val a = hex.substring(6, 8).toInt(16)
                android.graphics.Color.argb(a, r, g, b)
            } else {
                android.graphics.Color.parseColor(color)
            }
        } catch (e: Exception) {
            Log.e("MainActivity", "parseAnyColor failed for: $color", e)
            android.graphics.Color.TRANSPARENT
        }
    }

    // Removed animateTopInset: safe padding is always applied based on WindowInsets

    // Back button handling with WebView navigation
    override fun onBackPressed() {
        if (::webView.isInitialized && webView.canGoBack()) {
            // Check if we're on the main page (index.html or root)
            val currentUrl = webView.url ?: ""
            val serverUrl = getServerUrl()
            
            // If we're on main page or root, exit app
            if (currentUrl == serverUrl || 
                currentUrl == "$serverUrl/" ||
                currentUrl.endsWith("/index.html") ||
                currentUrl.endsWith("/")) {
                finish()
            } else {
                // Go back in WebView
                webView.goBack()
            }
        } else {
            // No history, exit app
            finish()
        }
    }

    override fun onPause() {
        super.onPause()
        try {
            // Save cookies when app goes to background
            val cookieManager = CookieManager.getInstance()
            cookieManager.flush()
            Log.d("MainActivity", "Cookies saved on pause")
        } catch (e: Exception) {
            Log.e("MainActivity", "Error saving cookies on pause", e)
        }
    }

    override fun onResume() {
        super.onResume()
        enableFullscreen()
        
        try {
            // Restore cookie settings when app resumes
            val cookieManager = CookieManager.getInstance()
            cookieManager.setAcceptCookie(true)
            if (::webView.isInitialized) {
                cookieManager.setAcceptThirdPartyCookies(webView, true)
            }
            Log.d("MainActivity", "Cookies restored on resume")
        } catch (e: Exception) {
            Log.e("MainActivity", "Error restoring cookies on resume", e)
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            enableFullscreen()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            // Clean up WebView
            webView.destroy()
        } catch (e: Exception) {
            Log.e("MainActivity", "Error destroying WebView", e)
        }
    }
}
