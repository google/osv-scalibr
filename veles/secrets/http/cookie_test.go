// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package http_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/http"
	"github.com/google/osv-scalibr/veles/velestest"
)

func TestCookieDetectorAcceptance(t *testing.T) {
	velestest.AcceptDetector(
		t,
		http.NewCookieDetector(),
		`HTTP/1.1 200 896 Cookie: "session_id=23rj302jr032mr03m2r03230r"`,
		http.Cookie{Name: "session_id", Value: "23rj302jr032mr03m2r03230r"},
	)
}

func TestCookieDetector_truePositives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewCookieDetector()})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		file  string
		input string
		want  []veles.Secret
	}{
		// Log formats
		{
			name: "pino_log",
			file: "logs/pino/app.log",
			want: []veles.Secret{
				http.Cookie{Name: "pino_session", Value: "xyz987"},
				http.Cookie{Name: "pino_session", Value: "xyz987"},
			},
		},
		{
			name: "dotnet_log",
			file: "logs/dotnet/vulnerable20260424.log",
			want: []veles.Secret{
				http.Cookie{Name: "session_id", Value: "abc123dotnet"},
				http.Cookie{Name: "session_id", Value: "abc123dotnet"},
			},
		},
		{
			name: "nginx_log",
			file: "logs/nginx/access.log",
			want: []veles.Secret{
				http.Cookie{Name: `tracking_id`, Value: `evil_corp_999`},
				http.Cookie{Name: `tracking_id`, Value: `evil_corp_999`},
			},
		},
		// Synthetic examples
		{
			name:  "basic_single_cookie",
			input: "Content-Type: text/html\nCookie: session_id=123456",
			want: []veles.Secret{
				http.Cookie{Name: "session_id", Value: "123456"},
			},
		},
		{
			name:  "quoted and encoded",
			input: "Content-Type: text/html\n" + `Cookie: "session_id=\"123456\""`,
			want: []veles.Secret{
				http.Cookie{Name: "session_id", Value: "123456"},
			},
		},
		{
			name:  "set-cookie_header",
			input: "Content-Type: application/json\nSet-Cookie: token=super_secret",
			want: []veles.Secret{
				http.Cookie{Name: "token", Value: "super_secret"},
			},
		},
		{
			name:  "case_insensitive_headers",
			input: "content-type: application/json\ncOokiE: mixed_case=val123",
			want: []veles.Secret{
				http.Cookie{Name: "mixed_case", Value: "val123"},
			},
		},
		{
			name:  "multiple_chained_cookies_with_spacing",
			input: "Content-Type: text/html\nCookie: a=1;   b=2; c=3",
			want: []veles.Secret{
				http.Cookie{Name: "a", Value: "1"},
				http.Cookie{Name: "b", Value: "2"},
				http.Cookie{Name: "c", Value: "3"},
			},
		},
		{
			name:  "base64_value_with_padding_equals_signs",
			input: "Content-Type: text/html\nCookie: auth=ZXhhbXBsZQ==; id=99",
			want: []veles.Secret{
				http.Cookie{Name: "auth", Value: "ZXhhbXBsZQ=="},
				http.Cookie{Name: "id", Value: "99"},
			},
		},
		{
			name:  "embedded_in_log_line_with_trailing_garbage_text",
			input: `INFO [2026-05-21] content-type: application/json user logged in Cookie: "user=admin; session=xyz123" [thread-4] status=200`,
			want: []veles.Secret{
				http.Cookie{Name: "user", Value: "admin"},
				http.Cookie{Name: "session", Value: "xyz123"},
			},
		},
		{
			name:  "ignores_valueless_flags_at_the_end_of_set-cookie",
			input: "Content-Type: application/json\nSet-Cookie: id=123; Secure; HttpOnly",
			want: []veles.Secret{
				http.Cookie{Name: "id", Value: "123"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.file != "" {
				var readErr error
				data, readErr = os.ReadFile(filepath.Join("testdata", tc.file))
				if readErr != nil {
					t.Fatal(readErr)
				}
			} else {
				data = []byte(tc.input)
			}

			got, derr := e.Detect(t.Context(), bytes.NewReader(data))
			if derr != nil {
				t.Fatal(derr)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("(-want +got): %s", diff)
			}
		})
	}
}

func TestCookieDetector_trueNegatives(t *testing.T) {
	e, err := veles.NewDetectionEngine([]veles.Detector{http.NewCookieDetector()})
	if err != nil {
		t.Fatal(err)
	}

	negCases := []struct {
		name  string
		file  string
		input string
	}{
		// Cookie is present but is not detected.
		{
			// There is not enough context to properly detect the cookie, this case will probably never be covered
			name: "postman",
			file: "postman/cookie.json",
		},
		{
			// It would be nice to cover this case but at the current stage of the detector it would lead over-complication and
			// potential false positives
			name: "cookie_in_open_collection",
			file: "bruno/cookie/Auth.yml",
		},
		// Cookie not present
		{
			name: "missing_cookie_in_open_collection",
			file: "bruno/cookie/UnAuth.yml",
		},
		// Synthetic examples
		{
			name:  "empty_cookie_header",
			input: "Cookie: ",
		},
		{
			name:  "just_a_semicolon",
			input: "Cookie: ;",
		},
		{
			name:  "similar_but_different_header",
			input: "X-Forwarded-Cookie: a=1",
		},
		{
			name:  "no_equals_sign",
			input: "Cookie: just_a_name;",
		},
		{
			name:  "malformed_name_with_colon",
			input: "Cookie: a:b=1",
		},
		{
			name:  "random_key_value_pair_without_cookie_prefix",
			input: "session=12345; auth=true",
		},
		// Potential false positives from source code syntax (TDD cases for filtering)
		{
			name:  "js_object_destructuring",
			input: `const { cookie: session_token=null } = req.headers;`,
		},
		{
			name:  "js_assignment_operator",
			input: `const metrics = { cookie: index+=1, other_header: 0 };`,
		},
		{
			name:  "python_equality_check",
			input: `rules = { "cookie": incoming_type=="admin" }`,
		},
		{
			name:  "env_var_interpolation",
			input: `curl -H "Cookie: session_id=${LATEST_SESSION}" https://api.example.com`,
		},
		// Real examples
		{
			// src: https://github.com/Tuhinshubhra/CMSeeK/blob/master/cmseekdb/header.py
			name: "CMSeek",
			input: `
			'Set-Cookie: ushahidi:-ushahidi',
        'Set-Cookie: SQ_SYSTEM_SESSION||squizedge.net:-sqm',
        'SC_ANALYTICS_GLOBAL_COOKIE:-score',
        'X-Blog: Serendipity||Set-Cookie: serendipity[||Set-Cookie: s9y_:-spity',
        'Set-Cookie: SEAMLESS_IDENTIFIER:-slcms',
        'Set-Cookie: ndxz_:-ibit',
        'Set-Cookie: grav-site-:-grav',
        'X-Powered-By: eZ Publish||Set-Cookie: eZSESSID:-ezpu',
        'Set-Cookie: exp_tracker||Set-Cookie: exp_last_activity||Set-Cookie: exp_last_visit||Set-Cookie: exp_csrf_token=:-exen',
        'X-Powered-By: e107||Set-Cookie: SESSE107COOKIE:-e107',
        'Set-Cookie: dnn_IsMobile||DNNOutputCache||DotNetNuke:-dnn',
        'X-Powered-By: Craft CMS||Set-Cookie: CraftSessionId:-craft',
        'X-Powered-By: ContentBox||Set-Cookie: LIGHTBOXSESSION:-cbox',
        'Set-Cookie: CONCRETE5:-con5',
        'Set-Cookie: flarum_session=:-flarum',
        'Set-Cookie: xf_session=||Set-Cookie: xf_csrf=:-xf',
        'Set-Cookie: fud_session_:-fudf',
        'Set-Cookie: phorum_session:-phorum',
        'Set-Cookie: yazdLastVisited=:-yazd',
        'Set-Cookie: ubbt_:-ubbt',
        'set-cookie: fornax_anonymousId=:-bigc',
        'Set-Cookie: bigwareCsid||Set-Cookie: bigWAdminID:-bigw',
        'Set-Cookie: MoodleSession||Set-Cookie: MOODLEID_:-mdle',
        'Set-Cookie: COSMOSHOP_:-cosmos',
        'Set-Cookie: Dynamicweb:-dweb',
        'Powered-By: PrestaShop||Set-Cookie: PrestaShop:-presta',
        'Demandware Secure Token||Demandware anonymous cookie||dwpersonalization_||dwanonymous_:-sfcc',
        'X-Shopify-Stage||set-cookie: _shopify||Set-Cookie: secure_customer_sig:-shopify',
        'Set-Cookie: _SOLUSQUARE:-solusquare',
        'Set-Cookie: _spree_store_session:-spree',
        'Set-Cookie: WHMCS:-whmcs',
        'Set-Cookie: (YaBBusername=|YaBBpassword=|YaBBSession|Y2User-(\d.*?)|Y2Pass-(\d.*?)|Y2Sess-(\d.*?))=:-yabb',
        'Set-Cookie: xmblv(a|b)=(\d.*?)\n:-xmb',
        'Set-Cookie: [a-zA-Z0-9]{5}_(lastpos|lastvisit)=:-pwind',
        'Set-Cookie: mybb\[(.*?)\]=:-mybb',
        'Set-Cookie: wcf(.*?)_cookieHash=:-bboard',
        'Set-Cookie: phpbb(.*?)=:-phpbb',
        'Set-Cookie: ses(\d+)=:-impage',
        'Set-Cookie: sid_customer_[a-zA-Z0-9]{5}=:-csc',
        'Set-Cookie: (ekmMsg|ekmpowershop):-ekmps'
			`,
		},
		{
			// src: https://github.com/openjdk/jdk/blob/master/test/jdk/java/net/CookieHandler/TestHttpCookie.java
			name: "openjdk",
			input: `
			* @summary Unit test for java.net.HttpCookie
import java.net.HttpCookie;
public class TestHttpCookie {
    private List<HttpCookie> cookies = null;
    // the header string to be parsed into HttpCookie instance.
    // A TestHttpCookie instance will be created to hold such a HttpCookie
    // object, and TestHttpCookie class has utility methods to check equality
    // between HttpCookie's real property and expected property.
    static TestHttpCookie test(String cookieHeader) {
        return new TestHttpCookie(cookieHeader);
    TestHttpCookie(String cHeader) {
            List<HttpCookie> cookies = HttpCookie.parse(cHeader);
            this.cookies = cookies;
            cookies = null;
    TestHttpCookie n(int index, String n) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || !n.equalsIgnoreCase(cookie.getName())) {
            raiseError("name", cookie.getName(), n);
    TestHttpCookie n(String n) { return n(0, n); }
    TestHttpCookie v(int index, String v) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || !v.equals(cookie.getValue())) {
            raiseError("value", cookie.getValue(), v);
    TestHttpCookie v(String v) { return v(0, v); }
    TestHttpCookie ver(int index, int ver) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || (ver != cookie.getVersion())) {
            raiseError("version", Integer.toString(cookie.getVersion()), Integer.toString(ver));
    TestHttpCookie ver(int ver) { return ver(0, ver); }
    TestHttpCookie p(int index, String p) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || !p.equals(cookie.getPath())) {
            raiseError("path", cookie.getPath(), p);
    TestHttpCookie p(String p) { return p(0, p); }
    TestHttpCookie nil() {
        if (cookies != null) {
    TestHttpCookie c(int index, String c) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || !c.equals(cookie.getComment())) {
            raiseError("comment", cookie.getComment(), c);
    TestHttpCookie c(String c) { return c(0, c); }
    TestHttpCookie cu(int index, String cu) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || !cu.equals(cookie.getCommentURL())) {
            raiseError("comment url", cookie.getCommentURL(), cu);
    TestHttpCookie cu(String cu) { return cu(0, cu); }
    TestHttpCookie dsc(int index, boolean dsc) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || (dsc != cookie.getDiscard())) {
            raiseError("discard", Boolean.toString(cookie.getDiscard()), Boolean.toString(dsc));
    TestHttpCookie dsc(boolean dsc) { return dsc(0, dsc); }
    TestHttpCookie d(int index, String d) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || !d.equalsIgnoreCase(cookie.getDomain())) {
            raiseError("domain", cookie.getDomain(), d);
    TestHttpCookie d(String d) { return d(0, d); }
    TestHttpCookie a(int index, long a) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || (a != cookie.getMaxAge())) {
            raiseError("max-age", Long.toString(cookie.getMaxAge()), Long.toString(a));
    TestHttpCookie a(long a) { return a(0, a); }
    TestHttpCookie port(int index, String p) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || !p.equals(cookie.getPortlist())) {
            raiseError("portlist", cookie.getPortlist(), p);
    TestHttpCookie port(String p) { return port(0, p); }
    TestHttpCookie httpOnly(int index, boolean b) {
        HttpCookie cookie = cookies.get(index);
        if (cookie == null || b != cookie.isHttpOnly()) {
            raiseError("HttpOnly", String.valueOf(cookie.isHttpOnly()), String.valueOf(b));
    TestHttpCookie httpOnly(boolean b) {
    static void eq(HttpCookie ck1, HttpCookie ck2, boolean same) {
        if (HttpCookie.domainMatches(domain, host) != matches) {
        sb.append("Cookie ").append(attr).append(" is ").append(realValue).
        test("set-cookie2: Customer=\"WILE_E_COYOTE\"; Version=\"1\"; Path=\"/acme\"")
        test("set-cookie2: Customer = \"WILE_E_COYOTE\"; Version = \"1\"; Path = \"/acme\"")
        test("set-cookie2: $Customer = \"WILE_E_COYOTE\"; Version = \"1\"; Path = \"/acme\"")
        // a 'full' cookie
        test("set-cookie2: Customer=\"WILE_E_COYOTE\"" +
        // a 'full' cookie, without leading set-cookie2 token
        // empty set-cookie string
        test("Set-Cookie2:Customer=\"dtftest\"; Discard; Secure; Domain=\".sun.com\"; Max-Age=\"100\"; Version=\"1\";  path=\"/www\"; Port=\"80\"")
        test("Set-Cookie2:Customer=\"dtftest\"; Discard; Secure; Domain=\".sun.com\"; Max-Age=\"100\"; Version=\"1\";  path=\"/www\"; Port=\"80\"" +
        test("Set-Cookie2:Customer=\"dtftest\";Discard; Secure; Domain=\"sun.com\"; Max-Age=\"100\";Version=\"1\";  Path=\"/www\"; Port=\"80,8080\"")
        test("Set-Cookie2:Customer=\"developer\";Domain=\"sun.com\";Max-Age=\"100\";Path=\"/www\";Port=\"80,8080\";CommentURL=\"http://www.sun.com/java1,000,000.html\"")
        // a header string contains 2 cookies
        test("Set-Cookie2:C1=\"V1\";Domain=\".sun1.com\";path=\"/www1\";Max-Age=\"100\",C2=\"V2\";Domain=\".sun2.com\";path=\"/www2\";Max-Age=\"200\"")
        test("Set-Cookie2:C1=\"V1\";foobar").n(0, "C1").v(0, "V1");
        header("Test using netscape cookie syntax");
        test("set-cookie: CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT")
        // a Netscape cookie, without set-cookie leading token
        // a 'google' cookie
        test("Set-Cookie: PREF=ID=1eda537de48ac25d:CR=1:TM=1112868587:LM=1112868587:S=t3FPA-mT9lTR3bxU;" +
        test("set-cookie: CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT; Secure")
        test("set-cookie: CUSTOMER=WILE_E_COYOTE; path=/; expires=Wednesday, 09-Nov-99 23:12:40 GMT; path=\"/acme\"")
        test("set-cookie: CUSTOMER=WILE_E_COYOTE; version='1'").ver(1);
        HttpCookie c1 = new HttpCookie("Customer", "WILE_E_COYOTE");
        HttpCookie c2 = (HttpCookie)c1.clone();
        c1 = new HttpCookie("Customer", "WILE_E_COYOTE");
        c2 = new HttpCookie("CUSTOMER", "WILE_E_COYOTE");
        c1 = new HttpCookie("Customer", "WILE_E_COYOTE");
        c2 = new HttpCookie("CUSTOMER", "WILE_E_COYOTE");
            c1 = new HttpCookie("", "whatever");
        test("set-cookie: CUSTOMER=WILE_E_COYOTE;HttpOnly").httpOnly(true);
        test("set-cookie: CUSTOMER=WILE_E_COYOTE").httpOnly(false);
        test("set-cookie: CUST OMER=WILE_E_COYOTE").nil();
			`,
		},
		{
			// src: https://github.com/filipedeschamps/tabnews.com.br/blob/main/tests/integration/api/v1/users/%5Busername%5D/delete.test.js
			name:  "tabnews",
			input: "          cookie: `session_id=${firstUserSession.token}`,",
		},
		{
			// HTTP dump present in source code, but not detected since the `(?:Set-)?Cookie` keyword does not appear at the start of the line
			// src: https://github.com/rapid7/metasploit-framework/blob/master/spec/lib/rex/proto/http/response_spec.rb
			name: "metasploit_src",
			input: `
	  let(:get_cookies_test_no_cookies) do
  let(:get_cookies_test_five_cookies) do
      Set-Cookie: phpMyAdmin=gpjif0gtpqbvfion91ddtrq8p8vgjtue; path=/phpmyadmin/; HttpOnly
      Set-Cookie: pma_lang=en; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: pma_collation_connection=utf8_general_ci; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: pma_mcrypt_iv=mF1NmTE64IY%3D; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: phpMyAdmin=fmilioji5cn4m8bo5vjrrr6q9cada954; path=/phpmyadmin/; HttpOnly
  let (:get_cookies_test_five_ordered_cookies) do
      Set-Cookie: pma_lang=en; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: pma_collation_connection=utf8_general_ci; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: pma_mcrypt_iv=mF1NmTE64IY%3D; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: phpMyAdmin=fmilioji5cn4m8bo5vjrrr6q9cada954; path=/phpmyadmin/; HttpOnly
      Set-Cookie: superC00kie!=stupidcookie; Path=/parp/; domain=.foo.com; HttpOnly; Expires=Wed, 13-Jan-2012 22:23:01 GMT; Secure
  let (:get_cookies_test_with_empty_cookie) do
      Set-Cookie: phpMyAdmin=gpjif0gtpqbvfion91ddtrq8p8vgjtue; path=/phpmyadmin/; HttpOnly
      Set-Cookie: pma_lang=en; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: pma_collation_connection=utf8_general_ci; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: pma_mcrypt_iv=mF1NmTE64IY%3D; expires=Sun, 26-May-2013 08:44:54 GMT; path=/phpmyadmin/; httponly
      Set-Cookie: phpMyAdmin=; path=/phpmyadmin/; HttpOnly
  let (:get_cookies_test_one_set_cookie_header) do
      Set-Cookie: wordpressuser_a97c5267613d6de70e821ff82dd1ab94=admin; path=/wordpress-2.0/, wordpresspass_a97c5267613d6de70e821ff82dd1ab94=c3284d0f94606de1fd2af172aba15bf3; path=/wordpress-2.0/
  let (:get_cookies_comma_separated) do
      Set-Cookie: cval=880350187, session_id_8000=83466b1a1a7a27ce13d35f78155d40ca3a1e7a28; expires=Mon, 07 Jul 2014 20:09:28 GMT; httponly; Path=/, uid=348637C4-9B10-485A-BFA9-5E892432FCFD; expires=Fri, 05-Jul-2019 20:09:28 GMT
  let (:get_cookies_spaces_and_missing_semicolon) do
      Set-Cookie: k1=v1; k2=v2;k3=v3
  def cookie_sanity_check(meth)
    cookies = resp.get_cookies
    expect(cookies).not_to be_nil
    expect(cookies).not_to be ''
    cookies.split(';').map(&:strip)
  context "#get_cookies" do
    it 'returns empty string for no Set-Cookies' do
      resp.parse(get_cookies_test_no_cookies)
      expect(resp.get_cookies).to eq('')
    it 'returns 5 cookies when given 5 cookies non-sequentially' do
      cookies_array = cookie_sanity_check(:get_cookies_test_five_cookies)
      expect(cookies_array.count).to eq(5)
      expect(cookies_array).to match_array %w(
    it 'returns and parses 5 cookies when given 5 ordered cookies' do
      cookies_array = cookie_sanity_check(:get_cookies_test_five_ordered_cookies)
      expect(cookies_array.count).to eq(5)
      expected_cookies = %w{
      superC00kie!=stupidcookie
      expected_cookies.shuffle!
      expect(cookies_array).to include(*expected_cookies)
    it 'parses an empty cookie value' do
      cookies_array = cookie_sanity_check(:get_cookies_test_with_empty_cookie)
      expect(cookies_array.count).to eq(5)
      expected_cookies = %w{
      expected_cookies.shuffle!
      expect(cookies_array).to include(*expected_cookies)
    it 'parses multiple cookies in one Set-Cookie header' do
      cookies_array = cookie_sanity_check(:get_cookies_test_one_set_cookie_header)
      expect(cookies_array.count).to eq(2)
      expected_cookies = %w{
      expected_cookies.shuffle!
      expect(cookies_array).to include(*expected_cookies)
    it 'parses comma separated cookies' do
      cookies_array = cookie_sanity_check(:get_cookies_comma_separated)
      expect(cookies_array.count).to eq(3)
      expected_cookies = %w{
      expected_cookies.shuffle!
      expect(cookies_array).to include(*expected_cookies)
    it 'parses cookies with inconsistent spacing and a missing trailing semicolons' do
      resp.parse(self.send :get_cookies_spaces_and_missing_semicolon)
      cookies = resp.get_cookies_parsed
      names = cookies.keys.sort
      cookies.each do |_, parsed|
`,
		},
	}

	for _, tc := range negCases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.file != "" {
				var readErr error
				data, readErr = os.ReadFile(filepath.Join("testdata", tc.file))
				if readErr != nil {
					t.Fatal(readErr)
				}
			} else {
				data = []byte(tc.input)
			}

			got, derr := e.Detect(t.Context(), bytes.NewReader(data))
			if derr != nil {
				t.Fatal(derr)
			}
			if diff := cmp.Diff([]veles.Secret(nil), got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("(-want +got): %s", diff)
			}
		})
	}
}
