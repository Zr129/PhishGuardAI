{
  "manifest_version": 3,
  "name": "Phishing Detector",
  "version": "1.0",
  "description": "Detect phishing sites using URL analysis",

  "permissions": ["activeTab", "scripting"],

  "background": {
    "service_worker": "background.js"
  },

  "action": {
    "default_popup": "popup.html"
  },

  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"]
    }
  ]
}