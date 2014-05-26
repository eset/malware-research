/*
 * Code related to ESET's Miniduke malware research
 * For feedback or questions contact us at: github@eset.com
 * https://github.com/eset/malware-research/
 *
 * This is the twitter username generation code that was extracted from the
 * sample's TwitterJS component. It contains no malicious payload, it just
 * generates and prints usernames.
 */

function twitterjs_sha1(s) {
    x = Q(s);
    z = s.length * 8;
    x[z >> 5] |= 0x80 << (24 - z % 32);
    x[((z + 64 >> 9) << 4) + 15] = z;
    w = Array(80);
    a = 1732584193;
    b = -271733879;
    c = -1732584194;
    d = 271733878;
    e = -1009589776;
    for (i = 0; i < x.length; i += 16) {
        q = a;
        f = b;
        g = c;
        h = d;
        k = e;
        for (j = 0; j < 80; j++) {
            if (j < 16) w[j] = x[i + j];
            else w[j] = Y(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            t = Z(Z(Y(a, 5), N(j, b, c, d)), Z(Z(e, w[j]), (j < 20) ? 1518500249 : (j < 40) ? 1859775393 : (j < 60) ? -1894007588 : -899497514));
            e = d;
            d = c;
            c = Y(b, 30);
            b = a;
            a = t
        }
        a = Z(a, q);
        b = Z(b, f);
        c = Z(c, g);
        d = Z(d, h);
        e = Z(e, k)
    }
    return Array(a, b, c, d, e)
}
function Z(x, y) {
    f = 0xffff;
    l = (x & f) + (y & f);
    m = (x >> 16) + (y >> 16) + (l >> 16);
    return (m << 16) | (l & f)
}
function N(t, b, c, d) {
    if (t < 20) return (b & c) | ((~b) & d);
    if (t < 40) return b ^ c ^ d;
    if (t < 60) return (b & c) | (b & d) | (c & d);
    return b ^ c ^ d
}

function Y(node_base_64, c) {
    return (node_base_64 << c) | (node_base_64 >>> (32 - c))
}
function Q(s) {
    p = Array(s.length >> 2);
    for (i = 0; i < s.length * 8; i += 8) p[i >> 5] |= (s.charCodeAt(i / 8) & 0xff) << (24 - i % 32);
    return p
}
node_base_64 = new ActiveXObject('MSXML2.DOMDocument').createElement('base64');
node_base_64.dataType = 'bin.base64';
for (var year = 2013; year <= 2014; year++) {
    for (var month = 0; month < 12; month++) {
        for (var week = 0; week <= 5; week++) {
            hash = twitterjs_sha1('' + week + month + year);

            y = new ActiveXObject('ADODB.Stream');
            y.Open;
            y.Type = 2;
            y.WriteText('' + hash[0] + hash[1] + hash[2]);
            y.Position = 0;
            y.Type = 1;
            // convert the date_seed to Base64
            node_base_64.nodeTypedValue = y.Read;
            y.Close;
            username = node_base_64.text.replace(/.*([A-Za-z]\w{14})/, '$1').substr(0, 7 + week);
            WScript.echo(year + '-' + (month+1) + " week " + (week+1) + " : " + username);
        }
    }
}
