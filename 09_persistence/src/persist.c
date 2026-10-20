#include "persist.h"
#include <stdio.h>

size_t persist_cron_line(const char *cmd, char *out, size_t cap) {
    if (!cmd || !out || cap == 0) return 0;
    int n = snprintf(out, cap, "* * * * * %s", cmd);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

size_t persist_systemd_unit(const char *name, const char *exec, char *out, size_t cap) {
    if (!name || !exec || !out || cap == 0) return 0;
    int n = snprintf(out, cap,
        "[Unit]\n"
        "Description=%s\n"
        "\n"
        "[Service]\n"
        "ExecStart=%s\n"
        "Restart=always\n"
        "RestartSec=60\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n", name, exec);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

size_t persist_launch_agent(const char *label, const char *exec, char *out, size_t cap) {
    if (!label || !exec || !out || cap == 0) return 0;
    int n = snprintf(out, cap,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "  <key>Label</key>\n"
        "  <string>%s</string>\n"
        "  <key>ProgramArguments</key>\n"
        "  <array>\n"
        "    <string>/bin/sh</string>\n"
        "    <string>-c</string>\n"
        "    <string>%s</string>\n"
        "  </array>\n"
        "  <key>RunAtLoad</key>\n"
        "  <true/>\n"
        "</dict>\n"
        "</plist>\n", label, exec);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}
