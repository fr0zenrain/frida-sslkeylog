"use strict"

function allocPointer(value) {
    const address = Memory.alloc(Process.pointerSize);

    Memory.writePointer(address, value);

    return address;
}

function queryPrefixFromMatch(match) {
    const name = match.name;

    const delimiterIndex = name.indexOf("!");
    const moduleQuery = name.substring(0, delimiterIndex + 1);

    return "exports:" + moduleQuery;
}

function dumpHexString(buffer){
    const byteArray = new Uint8Array(buffer);
    const hexParts = [];
    for(var i = 0; i< byteArray.length; i++){
        const hex = byteArray[i].toString(16);
        const paddedHex=('00'+hex).slice(-2);
        hexParts.push(paddedHex);
    }
    return hexParts.join('');
}

const resolver = new ApiResolver("module");

resolver.enumerateMatches("exports:*!SSL_connect", {
    onMatch: function (match) {
        const queryPrefix = queryPrefixFromMatch(match);

        function resolveExport(name) {
            const matches = resolver.enumerateMatchesSync(queryPrefix + name);

            if (matches.length == 0) {
                return null;
            }

            return matches[0].address;
        }

        function resolveFunction(name, returnType, argTypes) {
            const address = resolveExport(name);

            return new NativeFunction(address, returnType, argTypes);
        }

        const SSL_get_session = resolveFunction(
            "SSL_get_session", "pointer", ["pointer"]
        );

        const i2d_SSL_SESSION = resolveFunction(
            "i2d_SSL_SESSION", "int", ["pointer", "pointer"]
        );

        const SSL_get_client_random = resolveFunction(
            "SSL_get_client_random", "int", ["pointer", "pointer", 'int']
        );
        const SSL_SESSION_get_master_key = resolveFunction(
            "SSL_SESSION_get_master_key", "int", ["pointer", "pointer","int"]
        );
        const SSL_CTX_set_keylog_callback = resolveFunction(
            "SSL_CTX_set_keylog_callback", "int", ["pointer", "pointer","int"]
        );
        
        function encodeSSLSession(session) {
            const length = i2d_SSL_SESSION(session, NULL);
            const address = Memory.alloc(length);

            i2d_SSL_SESSION(session, allocPointer(address));

            return Memory.readByteArray(address, length);
        };

        function handleSSL(ssl) {
            const session = SSL_get_session(ssl);
            send("session", encodeSSLSession(session));
            var master=Memory.alloc(48);
            var random=Memory.alloc(32);
            SSL_get_client_random(ssl,random,32)
            SSL_SESSION_get_master_key(session,master,48);
            var master_key=Memory.readByteArray(master, 48);
            var client_random=Memory.readByteArray(random, 32);
            
            console.log('CLIENT_RANDOM',dumpHexString(client_random), dumpHexString(master_key));
        }

        Interceptor.attach(match.address, {
            onEnter: function(args) {
                this.ssl = args[0];
            },

            onLeave: function (retvalue) {
                handleSSL(this.ssl);
            }
        });

        function attachSSLExport(name) {
            Interceptor.attach(resolveExport(name), {
                onEnter: function (args) {
                    const ssl = args[0];
                    handleSSL(ssl);
                }
            });
        }

        attachSSLExport("SSL_read");
        attachSSLExport("SSL_write");
    },

    onComplete: function() {}
});