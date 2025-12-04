
// НЕ ЗАБЫТЬ ИНАЧЕ ТИМЛИД ПО ПОПКЕ ДАСТ
const ENCRYPTION_KEY = CryptoJS.enc.Utf8.parse('ObsidianWallKey!');
const INIT_VECTOR = CryptoJS.enc.Utf8.parse('ShadowGateKeepr!');

document.addEventListener("DOMContentLoaded", function() {
    const token = getCookie("auth_token");
    
    if (token) {
        try {
            const decrypted = decryptToken(token);
            
            console.log(
                "%c[ORDO NET] SESSION VERIFIED: " + decrypted.user, 
                "background: #000; color: #d4af37; padding: 5px; border: 1px solid #d4af37;"
            );
            
            if (decrypted.role === 'guest') {
                console.warn("%c[ACCESS] LEVEL 3 (MANAGER). CORE ACCESS: DENIED.", "color: #ff3e3e");
            } else if (decrypted.role === 'admin') {
                console.log("%c[ACCESS] LEVEL 1 (COUNCIL). CORE ACCESS: GRANTED.", "color: #0f0; font-weight: bold; font-size: 1.1em;");
            }
        } catch (e) {
            console.error("TOKEN ERROR. CONNECTION UNSTABLE.");
        }
    }
});

function decryptToken(encryptedBase64) {
    const decrypted = CryptoJS.AES.decrypt(encryptedBase64, ENCRYPTION_KEY, {
        iv: INIT_VECTOR,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}