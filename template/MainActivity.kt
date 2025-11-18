package com.mikrotik.manager

import android.annotation.SuppressLint
import android.app.DownloadManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.util.Log
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import android.webkit.CookieManager
import android.webkit.DownloadListener
import android.webkit.URLUtil
import android.webkit.WebResourceRequest
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
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen

class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var preferences: SharedPreferences

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        // Install splash screen with fast dismiss
        val splashScreen = installSplashScreen()
        splashScreen.setKeepOnScreenCondition { 
            // Keep splash for minimal time - just until we start loading
            false 
        }
        
        super.onCreate(savedInstanceState)
        window.setFlags(
            WindowManager.LayoutParams.FLAG_HARDWARE_ACCELERATED,
            WindowManager.LayoutParams.FLAG_HARDWARE_ACCELERATED
        )

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

            // Set dark background immediately to prevent white flash
            webView.setBackgroundColor(android.graphics.Color.parseColor("#111827"))
            
            // Make WebView invisible until content loads to prevent flash
            webView.visibility = View.INVISIBLE

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
                // Modern security settings for Android 15+
                @Suppress("DEPRECATION")
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
                    allowUniversalAccessFromFileURLs = false
                    allowFileAccessFromFileURLs = false
                }
                mediaPlaybackRequiresUserGesture = false
            }
            webView.overScrollMode = View.OVER_SCROLL_NEVER

            // Setup download handling for file downloads
            setupDownloadHandling()

            // Add JavaScript interface for theme-based status bar colors and downloads
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
                            // Use modern WindowInsetsController for Android 11+
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
                            }
                        } catch (e: Exception) {
                            Log.e("MainActivity", "Error setting status bar icons: $mode", e)
                        }
                    }
                }
                
                @android.webkit.JavascriptInterface
                fun downloadUrl(url: String) {
                    runOnUiThread {
                        try {
                            Log.d("MainActivity", "Download requested: $url")
                            startDownload(url)
                        } catch (e: Exception) {
                            Log.e("MainActivity", "Error starting download: $url", e)
                            Toast.makeText(this@MainActivity, "Chyba pri sťahovaní súboru", Toast.LENGTH_SHORT).show()
                        }
                    }
                }
                
                @android.webkit.JavascriptInterface
                fun confirmDeleteBackup(filename: String) {
                    runOnUiThread {
                        try {
                            Log.d("MainActivity", "Delete confirmation requested: $filename")
                            val builder = android.app.AlertDialog.Builder(this@MainActivity)
                            builder.setTitle("Vymazať zálohu")
                            builder.setMessage("Naozaj chcete vymazať záložný súbor \"$filename\"?\n\nTento súbor bude vymazaný lokálne aj z FTP servera (ak je nakonfigurovaný).")
                            builder.setPositiveButton("Vymazať") { _, _ ->
                                webView.evaluateJavascript("deleteBackupConfirmed('$filename')", null)
                            }
                            builder.setNegativeButton("Zrušiť", null)
                            builder.show()
                        } catch (e: Exception) {
                            Log.e("MainActivity", "Error showing delete confirmation: $filename", e)
                            Toast.makeText(this@MainActivity, "Chyba pri potvrdení vymazania", Toast.LENGTH_SHORT).show()
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

            // Custom WebViewClient for theme-based status bar and download handling
            webView.webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                    val url = request?.url?.toString()
                    if (url != null && isDownloadUrl(url)) {
                        Log.d("MainActivity", "Intercepting download URL: $url")
                        startDownload(url)
                        return true
                    }
                    return super.shouldOverrideUrlLoading(view, request)
                }
                
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    
                    // Show WebView only after content loads to prevent white flash
                    if (webView.visibility != View.VISIBLE) {
                        webView.visibility = View.VISIBLE
                    }
                    
                    // Force cookie sync after each page load
                    val cookieMgr = CookieManager.getInstance()
                    cookieMgr.flush()
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
                                    Android.setStatusBarColor('#cddbf2'); // Match light-mode background
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
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
                window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS)
            }

            // Default dark theme colors
            window.statusBarColor = android.graphics.Color.parseColor("#111827") // Dark theme
            window.navigationBarColor = android.graphics.Color.parseColor("#111827")

            // Normal layout - let system handle status bar space automatically
            WindowCompat.setDecorFitsSystemWindows(window, true)

            // Light icons for dark background - use modern API for Android 11+
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                window.insetsController?.setSystemBarsAppearance(
                    0, // Light icons
                    WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS
                )
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

    // Download handling methods
    private fun setupDownloadHandling() {
        webView.setDownloadListener(DownloadListener { url, _, _, _, _ ->
            Log.d("MainActivity", "Download listener triggered: $url")
            startDownload(url)
        })
    }
    
    private fun isDownloadUrl(url: String): Boolean {
        return url.contains("/download_backup/") || url.endsWith(".backup") || url.endsWith(".rsc")
    }
    
    private fun startDownload(url: String) {
        try {
            val request = DownloadManager.Request(Uri.parse(url))
            
            // Set cookies from WebView
            val cookies = CookieManager.getInstance().getCookie(url)
            if (!cookies.isNullOrEmpty()) {
                request.addRequestHeader("Cookie", cookies)
            }
            
            // Set User-Agent from WebView
            val userAgent = webView.settings.userAgentString
            if (!userAgent.isNullOrEmpty()) {
                request.addRequestHeader("User-Agent", userAgent)
            }
            
            // Extract filename from URL
            val filename = URLUtil.guessFileName(url, null, null)
            request.setTitle("Sťahovanie $filename")
            request.setDescription("MikroTik Manager - Sťahovanie zálohy")
            
            // Set destination
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Android 10+ - use scoped storage
                request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, filename)
            } else {
                // Android 9 and below - use legacy external storage
                request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, filename)
            }
            
            // Show download in notification
            request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            // Note: setVisibleInDownloadsUi is deprecated but harmless - Android handles this automatically
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                request.setVisibleInDownloadsUi(true)
            }
            
            // Start download
            val downloadManager = getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
            val downloadId = downloadManager.enqueue(request)
            
            Log.d("MainActivity", "Download started: ID=$downloadId, URL=$url")
            Toast.makeText(this, "Sťahovanie začalo: $filename", Toast.LENGTH_SHORT).show()
            
        } catch (e: Exception) {
            Log.e("MainActivity", "Error starting download", e)
            Toast.makeText(this, "Chyba pri sťahovaní súboru", Toast.LENGTH_LONG).show()
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
