/**
 * Supplemental Frida hooks for adversarial sandbox testing.
 * Monitors raw file access and network writes.
 */

Java.perform(function () {
    var File = Java.use('java.io.File');
    File.getPath.implementation = function () {
        var path = this.getPath();
        send({kind: 'file_access', path: path});
        return path;
    };

    var FileInputStream = Java.use('java.io.FileInputStream');
    FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
        send({kind: 'file_access', path: path, mode: 'read'});
        return this.$init(path);
    };
    FileInputStream.$init.overload('java.io.File').implementation = function (file) {
        if (file) {
            send({kind: 'file_access', path: file.getAbsolutePath(), mode: 'read'});
        }
        return this.$init(file);
    };

    // Monitor HttpURLConnection network output (Exfiltration)
    try {
        var HttpURLConnectionImpl = Java.use('com.android.okhttp.internal.huc.HttpURLConnectionImpl');
        HttpURLConnectionImpl.getOutputStream.implementation = function () {
            send({kind: 'network_payload', type: 'http_out', target: this.getURL().toString()});
            return this.getOutputStream();
        };
    } catch (e) {}
});

// Native libc hooks
Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
    onEnter: function (args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function (retval) {
        if (this.path && this.path.indexOf('CANARY') !== -1) {
            send({kind: 'file_access_native', path: this.path, fd: retval.toInt32()});
        }
    }
});
