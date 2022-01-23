export const CategoryInfo = {
    0: {
        risk: ``,
        cause: ``,
        recommendation: ``
    },
    418: {
        risk: `
A malicious user could access other users’ personal information, by simply altering the reference parameter sent to the server. Thus, the malicious user could bypass access controls and access unauthorized records, such as other users accounts, stealing confidential or restricted information.`,
        cause: `
The application accesses user information without filtering by user ID. For example, it may provide information solely by a submitted account ID. The application uses the user input to filter specific records from database tables, which contain sensitive personal information (e.g. user accounts or payment details). Since the application does not filter the records according to any user identifier, nor constrain it to a pre-computed list of acceptable values, a malicious user can easily modify the submitted reference identifier, and thus access unauthorized records.`,
        recommendation: `
Generic Guidance: 

    - Enforce authorization checks before providing any access to sensitive data, including the specific object reference. 
    
    - Explicitly block access to any unauthorized data, especially to other users’ data.
    
    - If possible, avoid allowing the user to request arbitrary data by simply sending a record ID. For example, instead of having the user send an account ID, the application should look up the account ID for the current authenticated user session.

Specific Mitigation:

    - Filter the database query according to a user-specific identifier, such as the customer number. 
    
    - Map the user input to an indirect reference, e.g. via a prepared list of allowable values.`
    },
    420: {
        risk: `
An attacker could directly access all of the system's data. The attacker would likely be able to steal any sensitive information stored by the system, including private user information, credit card details, proprietary business data, and any other secret data. Likewise, the attacker could possibly modify or erase existing data, or even add new bogus data. In some scenarios, it may even be possible to execute code on the database. 

In addition to disclosing or altering confidential information directly, this vulnerability might also be used to achieve secondary effects, such as bypassing authentication, subverting security checks, or forging a data trail. 

Further increasing the likelihood of exploit is the fact that this flaw is easy for attackers to find, and easy to exploit.

Note that in this case, the injection appears to be in an external component, which might be implementing its own internal checks.
`,
        cause: `
The application stores and manages data in a database, by submitting a textual SQL query to the database engine for processing. The application creates the query by simple string concatenation, embedding untrusted data. However, there is no separation between data and code; furthermore, the embedded data is neither checked for data type validity nor subsequently sanitized. Thus, the untrusted data could contain SQL commands, or modify the intended query. The database would interpret the altered query and commands as if they originated from the application, and execute them accordingly.

Note that the apparent database access is encapsulated in an external component or API. Thus, the attacker is able to inject arbitrary data into the SQL query, by way of altering the user input. This query is then passed to the API or component, where it is presumably submitted to the database server.`,
        recommendation: `
- Validate all untrusted data, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. 

- In particular, check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values.

- Restrict access to database objects and functionality, according to the Principle of Least Privilege.

- Do not use dynamically concatenate strings to construct SQL queries. 

- Prefer using DB Stored Procedures for all data access, instead of ad-hoc dynamic queries. 

- Instead of unsafe string concatenation, use secure database components such as parameterized queries and object bindings (for example, commands and parameters). 

- Alternatively, an even better solution is to use an ORM library, in order to pre-define and encapsulate the allowed commands enabled for the application, instead of dynamically accessing the database directly. In this way the code plane and data plane should be isolated from each other.

- Do not allow the user to dynamically provide the name of the queried table. Furthermore, if possible, completely avoid dynamically specifying table names. 

- Ensure that all exceptions are properly handled, without leaking information on the errors, server state, or that an error occurred at all.

- Prefer using database-specific DbCommand subclasses with DbParameter objects and API. Set the command's CommandType property to CommandType.StoredProcedure , and add the parameters to the .Parameters collection property instead of string concatenation. 

- Consider using an ORM library, such as Entity Framework, LINQ-To-SQL, nHibernate, or others.
`
    },
    426: {
        risk: `
An attacker that is able to alter the application’s LDAP query with arbitrary data would have control over the results returned from the User Directory server. Most commonly, this would enable an attacker to bypass authentication, or impersonate another user.  

Furthermore, this flaw can have various additional effects, depending on the architecture and usage model of the Directory service. Depending on how the application is using LDAP, the attacker could potentially do any of the following:

    - Bypass authentication
    - Impersonate another user
    - Subvert authorization
    - Escalate privileges
    - Modify user attributes and group membership
    - Access sensitive data
`,
        cause: `
The application communicates with an LDAP server, such as Active Directory, by sending a textual LDAP query or command. The application creates the query by simply concatenating strings, including untrusted data that may be controlled by an attacker. Since the data is neither validated nor properly sanitized, the input could contain LDAP commands that would be interpreted as such by the LDAP server.`,
        recommendation: `
Validate all external data, regardless of source. Validation should be based on a whitelist. Accept only data fitting a specified structure, rather than reject bad patterns.

Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

Avoid creating LDAP queries that are directly dependent on untrusted external data, if possible. For example, retrieve the user object from the LDAP server, and examine it's attributes in application code.

Consider replacing direct LDAP queries with a higher-level, uniform object model for user management or authentication, depending on LDAP usage. For example, the classes in the System.DirectoryServices.AccountManagement namespace including UserPrincipal, GroupPrincipal, PrincipalContext and more; or even the MembershipProvider or ASP.NET Identity models, as appropriate.
`
    },
    427: {
        risk: `
A successful XSS exploit would allow an attacker to rewrite web pages and insert malicious scripts which would alter the intended output. This could include HTML fragments, CSS styling rules, arbitrary JavaScript, or references to third party code. An attacker could use this to steal users' passwords, collect personal data such as credit card details, provide false information, or run malware. From the victim’s point of view, this is performed by the genuine website, and the victim would blame the site for incurred damage.

The attacker could use social engineering to cause the user to send the website modified input, which will be returned in the requested web page.`,
        cause: `
The application creates web pages that include untrusted data, whether from user input, the application’s database, or from other external sources. The untrusted data is embedded directly in the page's HTML, causing the browser to display it as part of the web page. If the input includes HTML fragments or JavaScript, these are displayed too, and the user cannot tell that this is not the intended page. The vulnerability is the result of directly embedding arbitrary data without first encoding it in a format that would prevent the browser from treating it like HTML or code instead of plain text.

Note that an attacker can exploit this vulnerability either by modifying the URL, or by submitting malicious data in the user input or other request fields.`,
        recommendation: `
- Fully encode all dynamic data, regardless of source, before embedding it in output.

- Encoding should be context-sensitive. For example:
    - HTML encoding for HTML content
    - HTML Attribute encoding for data output to attribute values
    - JavaScript encoding for server-generated JavaScript

- It is recommended to use the platform-provided encoding functionality, or known security libraries for encoding output.

- Implement a Content Security Policy (CSP) with explicit whitelists for the application's resources only. 

- As an extra layer of protection, validate all untrusted data, regardless of source (note this is not a replacement for encoding). Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

- In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page. 

- Set the HTTPOnly flag on the session cookie for "Defense in Depth", to prevent any successful XSS exploits from stealing the cookie.

- In .NET, when using Razor, consider that Razor is effective at sanitizing some HTML meta-characters, such as <, >, ', ", but ignores characters that may use to evade sanitization in Javascript contexts and result in XSS, such as \, \` and line breaks. Consider Razor as a safe sanitizer only when outputting dynamic data in an HTML context.`
    },
    429: {
        risk: `
An attacker could directly access all of the system's data. The attacker would likely be able to steal any sensitive information stored by the system, including private user information, credit card details, proprietary business data, and any other secret data. Likewise, the attacker could possibly modify or erase existing data, or even add new bogus data. In some scenarios, it may even be possible to execute code on the database. 

In addition to disclosing or altering confidential information directly, this vulnerability might also be used to achieve secondary effects, such as bypassing authentication, subverting security checks, or forging a data trail. 

Further increasing the likelihood of exploit is the fact that this flaw is easy for attackers to find, and easy to exploit.`,
        cause: `
The application stores and manages data in a database, by submitting a textual SQL query to the database engine for processing. The application creates the query by simple string concatenation, embedding untrusted data. However, there is no separation between data and code; furthermore, the embedded data is neither checked for data type validity nor subsequently sanitized. Thus, the untrusted data could contain SQL commands, or modify the intended query. The database would interpret the altered query and commands as if they originated from the application, and execute them accordingly.

In order to exploit this vulnerability, an attacker would load the malicious payload into the database, typically via forms on other web pages. Afterwards, the application reads this data from the database, and embeds it within the SQL query, as SQL commands.
`,
        recommendation: `
- Validate all untrusted data, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. 

- In particular, check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values.

- Restrict access to database objects and functionality, according to the Principle of Least Privilege.

- Do not use dynamically concatenate strings to construct SQL queries. 

- Prefer using DB Stored Procedures for all data access, instead of ad-hoc dynamic queries. 

- Instead of unsafe string concatenation, use secure database components such as parameterized queries and object bindings (for example, commands and parameters). 

- Alternatively, an even better solution is to use an ORM library, in order to pre-define and encapsulate the allowed commands enabled for the application, instead of dynamically accessing the database directly. In this way the code plane and data plane should be isolated from each other.

- Do not allow the user to dynamically provide the name of the queried table. Furthermore, if possible, completely avoid dynamically specifying table names. 

- Ensure that all exceptions are properly handled, without leaking information on the errors, server state, or that an error occurred at all.

- Prefer using database-specific DbCommand subclasses with DbParameter objects and API. Set the command's CommandType property to CommandType.StoredProcedure , and add the parameters to the .Parameters collection property instead of string concatenation. 

- Consider using an ORM library, such as Entity Framework, LINQ-To-SQL, nHibernate, or others.
`
    },
    430: {
        risk: `
An attacker could directly access all of the system's data. The attacker would likely be able to steal any sensitive information stored by the system, including private user information, credit card details, proprietary business data, and any other secret data. Likewise, the attacker could possibly modify or erase existing data, or even add new bogus data. In some scenarios, it may even be possible to execute code on the database. 

In addition to disclosing or altering confidential information directly, this vulnerability might also be used to achieve secondary effects, such as bypassing authentication, subverting security checks, or forging a data trail. 

Further increasing the likelihood of exploit is the fact that this flaw is easy for attackers to find, and easy to exploit.`,
        cause: `
The application stores and manages data in a database, by submitting a textual SQL query to the database engine for processing. The application creates the query by simple string concatenation, embedding untrusted data. However, there is no separation between data and code; furthermore, the embedded data is neither checked for data type validity nor subsequently sanitized. Thus, the untrusted data could contain SQL commands, or modify the intended query. The database would interpret the altered query and commands as if they originated from the application, and execute them accordingly.

Note that an attacker can exploit this vulnerability either by modifying the URL, or by submitting malicious data in the user input or other request fields.`,
        recommendation: `
- Validate all untrusted data, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. 

- In particular, check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values.

- Restrict access to database objects and functionality, according to the Principle of Least Privilege.

- Do not use dynamically concatenate strings to construct SQL queries. 

- Prefer using DB Stored Procedures for all data access, instead of ad-hoc dynamic queries. 

- Instead of unsafe string concatenation, use secure database components such as parameterized queries and object bindings (for example, commands and parameters). 

- Alternatively, an even better solution is to use an ORM library, in order to pre-define and encapsulate the allowed commands enabled for the application, instead of dynamically accessing the database directly. In this way the code plane and data plane should be isolated from each other.

- Do not allow the user to dynamically provide the name of the queried table. Furthermore, if possible, completely avoid dynamically specifying table names. 

- Ensure that all exceptions are properly handled, without leaking information on the errors, server state, or that an error occurred at all.

- Prefer using database-specific DbCommand subclasses with DbParameter objects and API. Set the command's CommandType property to CommandType.StoredProcedure , and add the parameters to the .Parameters collection property instead of string concatenation. 

- Consider using an ORM library, such as Entity Framework, LINQ-To-SQL, nHibernate, or others.
`
    },
    434: {
        risk: `
An attacker could directly access all of the system's data. The attacker would likely be able to steal any sensitive information stored by the system, including private user information, credit card details, proprietary business data, and any other secret data. Likewise, the attacker could possibly modify or erase existing data, or even add new bogus data. In some scenarios, it may even be possible to execute code on the database. 

In addition to disclosing or altering confidential information directly, this vulnerability might also be used to achieve secondary effects, such as bypassing authentication, subverting security checks, or forging a data trail. 

Further increasing the likelihood of exploit is the fact that this flaw is easy for attackers to find, and easy to exploit.

In this case, while the actual exploit is constrained to single bit of information at a time, it is still possible to eventually retrieve all data from the system, though this process is more time consuming and would be rather noisy. Note that other consequences, such as data modification and creation, code execution, etc. are unaffected, and still equally exploitable.`,
        cause: `
The application stores and manages data in a database, by submitting a textual SQL query to the database engine for processing. The application creates the query by simple string concatenation, embedding untrusted data. However, there is no separation between data and code; furthermore, the embedded data is neither checked for data type validity nor subsequently sanitized. Thus, the untrusted data could contain SQL commands, or modify the intended query. The database would interpret the altered query and commands as if they originated from the application, and execute them accordingly.

In this case, the attacker does not need to rely on the application returning data from the database. Instead, it is possible to leverage existing tools that perform a series of boolean tests based on varying user input, relying only on the existence of application errors to indicate server state. Thus, the full database content can gradually be obtained, one bit at a time.`,
        recommendation: `
- Validate all untrusted data, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. 

- In particular, check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values.

- Restrict access to database objects and functionality, according to the Principle of Least Privilege.

- Do not use dynamically concatenate strings to construct SQL queries. 

- Prefer using DB Stored Procedures for all data access, instead of ad-hoc dynamic queries. 

- Instead of unsafe string concatenation, use secure database components such as parameterized queries and object bindings (for example, commands and parameters). 

- Alternatively, an even better solution is to use an ORM library, in order to pre-define and encapsulate the allowed commands enabled for the application, instead of dynamically accessing the database directly. In this way the code plane and data plane should be isolated from each other.

- Do not allow the user to dynamically provide the name of the queried table. Furthermore, if possible, completely avoid dynamically specifying table names. 

- Ensure that all exceptions are properly handled, without leaking information on the errors, server state, or that an error occurred at all.

- Prefer using database-specific DbCommand subclasses with DbParameter objects and API. Set the command's CommandType property to CommandType.StoredProcedure , and add the parameters to the .Parameters collection property instead of string concatenation. 

- Consider using an ORM library, such as Entity Framework, LINQ-To-SQL, nHibernate, or others.
`
    },
    437: {
        risk: `
Unreleased resources can cause a drain of those available for system use, eventually causing general reliability and availability problems, such as performance degradation, process bloat, and system instability. If a resource leak can be intentionally exploited by an attacker, it may be possible to cause a widespread DoS (Denial of Service) attack. This might even expose sensitive information between unprivileged users, if the resource continues to retain data or user id between subsequent allocations.`,
        cause: `
The application code allocates resource objects, but does not ensure these are always closed and released in a timely manner. This can include database connections, file handles, network sockets, or any other resource that needs to be released. In some cases, these might be released - but only if everything works as planned; if there is any runtime exception during the normal course of system operations, resources start to leak. 

Note that even in managed-memory languages such as Java, these resources must be explicitly released. Many types of resource are not released even when the Garbage Collector runs; and even if the the object would eventually release the resource, we have no control over when the Garbage Collector does run.
`,
        recommendation: `
- Always close and release all resources.

- Ensure resources are released (along with any other necessary cleanup) in a finally { } block. Do not close resources in a catch { } block, since this is not ensured to be called. 

- Explicitly call .close() on any instance of a class that implements the Closable or AutoClosable interfaces. 

- Alternatively, an even better solution is to use the try-with-resources idiom, in order to automatically close any defined AutoClosable instances.`
    },
    439: {
        risk: `
If a security decision, such as access control for example, is taken based on unsanitized, user-controlled data, it may be possible for an attacker to manipulate the format of the data, and thus obfuscate the actual target. For example, if users are allowed to read any page that has their user id in the URL, a user can request a URL with multiple user ids. Another example could be an administrative interface, wherein users are forbidden from accessing any page under the /admin/ folder; an attacker can hide the actual target by sending a request to /NOTEXISTS/../admin/ . This would evade the check for URLs starting with "admin/", if the request URL is not canonicalized before checking.`,
        cause: `
Filesystem paths and Internet URLs can be represented in an unlimited number of different ways, using various encodings, folder misdirection, and path obfuscation techniques. If a path or address is not properly sanitized and fully canonicalized into it's most basic, simplified form, it would be impossible to check all possible variants of this path. Hence, any decision based on a specific attributes of the path would likely be mistaken, and can be evaded by an active attacker.`,
        recommendation: `
- Avoid performing security decisions based on untrusted, user-controlled input. 

- Always sanitize all user input. 

- Before making any decision based on a URL or path parameter, always transform it first into its canonical form, before making any decisions or doing any checks on it.
`
    },
    441: {
        risk: `
Hardcoded passwords expose the application to password leakage. If an attacker gains access to the source code, she will be able to steal the embedded passwords, and use them to impersonate a valid user. This could include impersonating end users to the application, or impersonating the application to a remote system, such as a database or a remote web service. 

Once the attacker succeeds in impersonating the user or application, she will have full access to the system, and be able to do anything the impersonated identity could do.`,
        cause: `
The application codebase has string literal passwords embedded in the source code. This hardcoded value is used either to compare to user-provided credentials, or to authenticate downstream to a remote system (such as a database or a remote web service).  

An attacker only needs to gain access to the source code to reveal the hardcoded password. Likewise, the attacker can reverse engineer the compiled application binaries, and easily retrieve the embedded password. Once found, the attacker can easily use the password in impersonation attacks, either directly on the application or to the remote system. 

Furthermore, once stolen, this password cannot be easily changed to prevent further misuse, unless a new version of the application is compiled. Moreover, if this application is distributed to numerous systems, stealing the password from one system automatically allows a class break in to all the deployed systems.`,
        recommendation: `
- Do not hardcode any secret data in source code, especially not passwords. 

- In particular, user passwords should be stored in a database or directory service, and protected with a strong password hash (e.g. bcrypt, scrypt, PBKDF2, or Argon2). Do not compare user passwords with a hardcoded value. 

- System passwords should be stored in a configuration file or the database, and protected with strong encryption (e.g. AES-256). Encryption keys should be securely managed, and not hardcoded.
`
    },
    443: {
        risk: `
An attacker could maliciously cause an exception that could crash the application, potentially resulting in a denial of service (DoS) or unexpected behavior under certain erroneous conditions. Exceptions may also occur without any malicious intervention, resulting in general instability.`,
        cause: `
The application performs some operation, such as database or file access, that could throw an exception. Since the application is not designed to properly handle the exception, the application could crash.`,
        recommendation: `
Any method that could cause an exception should be wrapped in a try-catch block that:

- Explicitly handles expected exceptions

- Includes a default solution to explicitly handle unexpected exceptions
`
    },
    445: {
        risk: `
Database transactions that are abandoned (if their associated connection is closed, before the transaction is committed or rolled back) can have several different results, depending on implementation and specific technologies in use. While in some scenarios the database will automatically roll back the transaction if the connection is closed, more often it will either automatically commit the transaction in its abortive state, or leave the transaction open indefinitely (depending on its configured timeout value). 

In the first case, a transaction that is committed after a runtime exception is likely to be in an inconsistent state, incompatible with the current runtime conditions. This would result in situation detrimental to the system's integrity and possibly even stability. 

In the second case, a transaction that is kept active indefinitely would cause the database server to retain its locks on all records and tables affected by the transaction. This could cause general reliability and availability problems, leading to delays, degraded performance, or even deadlocks as one thread waits for the locks to be released. 

In either case this results in unexpected state, and is dependent on external factors such that the application is not controlling the result.`,
        cause: `
The application creates a connection to the database, and explicitly manages the database transaction by committing it when appropriate. However, the code does not explicitly roll back failed transactions, for example in the case of exceptions. This causes the application to rely on implementation-specific behavior, depending on the specific combination of technologies (such as the database server) and resultant configuration.`,
        recommendation: `
- Always open database connections and begin transactions within a try { } block. 

- Ensure there are no active uncommitted transactions before closing a database connection. 

- Always rollback active transactions in the case of exceptions.

- After handling the exception, ensure the transaction is rolled back in the catch { } block, or possibly in the finally { } block.
`
    },
    448: {
        risk: `
An attacker could engineer audit logs of security-sensitive actions and lay a false audit trail, potentially implicating an innocent user or hiding an incident.`,
        cause: `
The application writes audit logs upon security-sensitive actions. Since the audit log includes user input that is neither checked for data type validity nor subsequently sanitized, the input could contain false information made to look like legitimate audit log data`,
        recommendation: `
Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

Validation is not a replacement for encoding. Fully encode all dynamic data, regardless of source, before embedding it in logs.

Use a secure logging mechanism.
`
    },
    459: {
        risk: `
An attacker could use social engineering to get a victim to click a link to the application, so that the user will be immediately redirected to another site of the attacker's choice. An attacker can then craft a destination website to fool the victim; for example - they may craft a phishing website with an identical looking UI as the previous website's login page, and with a similar looking URL, convincing the user to submit their access credentials in the attacker's website. Another example would be a phishing website with an identical UI as that of a popular payment service, convincing the user to submit their payment information.`,
        cause: `
The application redirects the user’s browser to a URL provided by a tainted input, without first ensuring that URL leads to a trusted destination, and without warning users that they are being redirected outside of the current site. An attacker could use social engineering to get a victim to click a link to the application with a parameter defining another site to which the application will redirect the user’s browser. Since the user may not be aware of the redirection, they may be under the misconception that the website they are currently browsing can be trusted.`,
        recommendation: `
- Ideally, do not allow arbitrary URLs for redirection. Instead, create a mapping from user-provided parameter values to legitimate URLs.

- If it is necessary to allow arbitrary URLs:

    - For URLs inside the application site, first filter and encode the user-provided parameter, and then either:

- Create a white-list of allowed URLs inside the application

- Use variables as a relative URL as an absolute one, by prefixing it with the application site domain - this will ensure all redirection will occur inside the domain

    - For URLs outside the application (if necessary), either:

- White-list redirection to allowed external domains by first filtering URLs with trusted prefixes. Prefixes must be tested up to the third slash [/] - scheme://my.trusted.domain.com/, to prevent evasion. For example, if the third slash [/] is not validated and scheme://my.trusted.domain.com is trusted, the URL scheme://my.trusted.domain.com.evildomain.com would be valid under this filter, but the domain actually being browsed is evildomain.com, not domain.com.

- For fully dynamic open redirection, use an intermediate disclaimer page to provide users with a clear warning that they are leaving the site.
`
    },
    460: {
        risk: `
Exposed details about the application’s environment, users, or associated data (for example, stack trace) could enable an attacker to find another flaw and help the attacker to mount an attack. This may also leak sensitive data, e.g. passwords or database fields.`,
        cause: `
The application handles exceptions in an insecure manner, including raw details directly in the error message. This could occur in various ways: by not handling the exception; printing it directly to the output or file; explicitly returning the exception object; or by configuration. These exception details may include sensitive information that could leak to the users due to the occurrence of the runtime error.`,
        recommendation: `
- Do not expose exception data directly to the output or users, instead return an informative, generic error message. Log the exception details to a dedicated log mechanism. 

- Any method that could throw an exception should be wrapped in an exception handling block that:

    - Explicitly handles expected exceptions.

    - Includes a default solution to explicitly handle unexpected exceptions.

- Configure a global handler to prevent unhandled errors from leaving the application.    `
    },
    463: {
        risk: `
A successful XSS exploit would allow an attacker to rewrite web pages and insert malicious scripts which would alter the intended output. This could include HTML fragments, CSS styling rules, arbitrary JavaScript, or references to third party code. An attacker could use this to steal users' passwords, collect personal data such as credit card details, provide false information, or run malware. From the victim’s point of view, this is performed by the genuine website, and the victim would blame the site for incurred damage.

The attacker could use legitimate access to the application to submit modified data, which would be returned as output without proper sanitization. This would then be used to dynamically generate output to a generic output writer - in some scenarios, such as with CGI scripts, this output is sent directly to the user's browser, which would trigger the attack.`,
        cause: `
The application creates web pages that include untrusted data, whether from user input, the application’s database, or from other external sources. The untrusted data is embedded directly in the page's HTML, causing the browser to display it as part of the web page. If the input includes HTML fragments or JavaScript, these are displayed too, and the user cannot tell that this is not the intended page. The vulnerability is the result of directly embedding arbitrary data without first encoding it in a format that would prevent the browser from treating it like HTML or code instead of plain text.

Note that an attacker can exploit this vulnerability either by modifying the URL, or by submitting malicious data in the user input or other request fields.`,
        recommendation: `
- Fully encode all dynamic data, regardless of source, before embedding it in output.

- Encoding should be context-sensitive. For example:

    - HTML encoding for HTML content

    - HTML Attribute encoding for data output to attribute values

    - JavaScript encoding for server-generated JavaScript

- It is recommended to use the platform-provided encoding functionality, or known security libraries for encoding output.

- Implement a Content Security Policy (CSP) with explicit whitelists for the application's resources only. 

- As an extra layer of protection, validate all untrusted data, regardless of source (note this is not a replacement for encoding). Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

- In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page. 

- Set the HTTPOnly flag on the session cookie for "Defense in Depth", to prevent any successful XSS exploits from stealing the cookie.`
    },
    464: {
        risk: `
An attacker could compromise the browser's Same Origin Policy and violate a user's privacy, by manipulating the browser's History object in JavaScript. This could allow the attacker in certain situations to detect whether the user is logged in, track the user's activity, or infer the state of other conditional values. This may also enhance Cross Site Request Forgery (XSRF) attacks, by leaking the result of the initial attack.`,
        cause: `
Modern browsers expose the user's browsing history to local JavaScript as a stack of previously visited URLs. While the browsers enforce a strict Same Origin Policy (SOP) to prevent pages from one website from reading visited URLs on other websites, the History object does leak the size of the history stack. Using only this information, in some situations the attacker can discover the results of certain checks the application server performs.

For example - if the application redirects an unauthenticated user to the login page, a script on another website can detect whether or not the user is logged in, by checking the length of the history object. This is done by first making a request to the page being redirected to (e.g. "/login"), then replacing that with a redirecting page that only redirects users if that user is not yet authenticated (e.g. "/profile") - if the length of history object remains the same, redirection has occurred back to the page being redirected to, and the history stack is not updated. If the history stack length is updated, that means the page did not redirect the user, causing the new page to be stored in the history stack.

This information leakage is enabled when the application redirects the user's browser based on the value of some condition, the state of the user's server-side session. e.g. whether the user is authenticated to the application, if the user has visited a certain page with specific parameters, or the value of some application data.

Note that this issue does not affect all browsers, and depends on the browser's implementation of Javascript's history object behavior.`,
        recommendation: `
- Add the response header "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" to all sensitive pages in the application, to protect against the IFrame version of XSHM in modern browser versions.

- Add a random value to all redirection URLs as a parameter to ensure that they are unique when inserted into the history stack`
    },
    465: {
        risk: `
An attacker could directly access all of the system's data. Using simple tools and text editing, the attacker would be able to steal any sensitive information stored in the server cache (such as personal user details or credit cards), and possibly change or erase existing data that could be subsequently used for other users or relied upon for security decisions. The application stores temporary data in its cache, and queries this data. The application creates the query by simply concatenating strings including the user's input. Since the user input is neither checked for data type validity nor subsequently sanitized, the input could contain commands that would be interpreted as such.`,
        cause: `
There are many different kinds of mistakes that introduce information exposures. The severity of the error can range widely, depending on the context in which the product operates, the type of sensitive information that is revealed, and the benefits it may provide to an attacker. Some kinds of sensitive information include:

    - private, personal information, such as personal messages, financial data, health records, geographic location, or contact details
    - system status and environment, such as the operating system and installed packages
    - business secrets and intellectual property
    - network status and configuration
    - the product's own code or internal state
    - metadata, e.g. logging of connections or message headers
    - indirect information, such as a discrepancy between two internal operations that can be observed by an outsider
    - Information might be sensitive to different parties, each of which may have their own expectations for whether the information should be protected. These parties include:

the product's own users
    - people or organizations whose information is created or used by the product, even if they are not direct product users
    - the product's administrators, including the admins of the system(s) and/or networks on which the product operates
    - the developer

Information exposures can occur in different ways:

    - the code explicitly inserts sensitive information into resources or messages that are intentionally made accessible to unauthorized actors, but should not contain the information - i.e., the information should have been "scrubbed" or "sanitized"
    - a different weakness or mistake indirectly inserts the sensitive information into resources, such as a web script error revealing the full system path of the program.
    - the code manages resources that intentionally contain sensitive information, but the resources are unintentionally made accessible to unauthorized actors. In this case, the information exposure is resultant - i.e., a different weakness enabled the access to the information in the first place.`,
        recommendation: `
- Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

- Instead of concatenating strings:

    - Use secure database components such as stored procedures, parameterized queries, and object bindings (for commands and parameters).

    - An even better solution is to use an ORM library, such as EntityFramework, Hibernate, or iBatis.

- Restrict access to database objects and functionality, according to the Principle of Least Privilege.

- If possible, avoid making security decisions based on cached data, especially data shared between users.`
    },
    468: {
        risk: `
An attacker could define arbitrary file path for the application to use, potentially leading to:

    - Stealing sensitive files, such as configuration or system files

    - Overwriting files such as program binaries, configuration files, or system files

    - Deleting critical files, causing denial of service (DoS).`,
        cause: `
The application uses user input in the file path for accessing files on the application server’s local disk.`,
        recommendation: `
- Ideally, avoid depending on dynamic data for file selection.

- Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

- Accept dynamic data only for the filename, not for the path and folders.

- Ensure that file path is fully canonicalized.

- Explicitly limit the application to use a designated folder that is separate from the applications binary folder.

- Restrict the privileges of the application’s OS user to necessary files and folders. The application should not be able to write to the application binary folder, and should not read anything outside of the application folder and data folder.`
    },
    471: {
        risk: `
If the header setting code is of a vulnerable version, an attacker could:

    - Arbitrarily change the application server’s response header to a victim’s HTTP request by manipulating headers

    - Arbitrarily change the application server’s response body by injecting two consecutive line breaks, which may result in Cross-Site Scripting (XSS) attacks

    - Cause cache poisoning, potentially controlling any site’s HTTP responses going through the same proxy as this application.`,
        cause: `
Since user input is being used in an HTTP response header, an attacker could include NewLine characters to make the header look like multiple headers with engineered content, potentially making the response look like multiple responses (for example, by engineering duplicate content-length headers). This can cause an organizational proxy server to provide the second, engineered response to a victim’s subsequent request; or, if the proxy server also performs response caching, the attacker can send an immediate subsequent request to another site, causing the proxy server to cache the engineered response as a response from this second site and to later serve the response to other users.

Many modern web frameworks mitigate this issue, by offering sanitization for new line characters in strings inserted into headers by default. However, since many older versions of web frameworks fail to automatically mitigate this issue, manual sanitization of input may be required.`,
        recommendation: `
- Validate all input, regardless of source (including cookies). Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

- Additionally, remove or URL-encode all special (non-alphanumeric) user input before including it in the response header.

- Make sure to use an up-to-date framework.`
    },
    474: {
        risk: `A malicious user could access other users’ information. By requesting information directly, such as by an account number, authorization may be bypassed and the attacker could steal confidential or restricted information (for example, a bank account balance), using a direct object reference.`,
        cause: `The application provides user information without filtering by user ID. For example, it may provide information solely by a submitted account ID. The application concatenates the user input directly into the SQL query string, without any additional filtering. The application also does not perform any validation on the input, nor constrain it to a pre-computed list of acceptable values.`,
        recommendation: `
Generic Guidance: 

    - Enforce authorization checks before providing any access to sensitive data, including the specific object reference. 

    - Explicitly block access to any unauthorized data, especially to other users’ data.

    - If possible, avoid allowing the user to request arbitrary data by simply sending a record ID. For example, instead of having the user send an account ID, the application should look up the account ID for the current authenticated user session.

Specific Mitigation:

    - Do not concatenate user input directly into SQL queries. 

    - Include a user-specific identifier as a filter in the WHERE clause of the SQL query. 

    - Map the user input to an indirect reference, e.g. via a prepared list of allowable values.`
    },
    479: {
        risk: `
A successful XSS exploit would allow an attacker to rewrite web pages and insert malicious scripts which would alter the intended output. This could include HTML fragments, CSS styling rules, arbitrary JavaScript, or references to third party code. An attacker could use this to steal users' passwords, collect personal data such as credit card details, provide false information, or run malware. From the victim’s point of view, this is performed by the genuine website, and the victim would blame the site for incurred damage.

The attacker could use social engineering to cause the user to send the website modified input, which will be returned in the requested web page.
`,
        cause: `
The application creates web pages that include untrusted data, whether from user input, the application’s database, or from other external sources. The untrusted data is embedded directly in the page's HTML, causing the browser to display it as part of the web page. If the input includes HTML fragments or JavaScript, these are displayed too, and the user cannot tell that this is not the intended page. The vulnerability is the result of directly embedding arbitrary data without first encoding it in a format that would prevent the browser from treating it like HTML or code instead of plain text.

Note that an attacker can exploit this vulnerability either by modifying the URL, or by submitting malicious data in the user input or other request fields.`,
        recommendation: `
- Fully encode all dynamic data, regardless of source, before embedding it in output.

- Encoding should be context-sensitive. For example:

    - HTML encoding for HTML content
    - HTML Attribute encoding for data output to attribute values
    - JavaScript encoding for server-generated JavaScript

- It is recommended to use the platform-provided encoding functionality, or known security libraries for encoding output.

- Implement a Content Security Policy (CSP) with explicit whitelists for the application's resources only. 

- As an extra layer of protection, validate all untrusted data, regardless of source (note this is not a replacement for encoding). Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

- In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page. 

- Set the HTTPOnly flag on the session cookie for "Defense in Depth", to prevent any successful XSS exploits from stealing the cookie.

- In .NET, when using Razor, consider that Razor is effective at sanitizing some HTML meta-characters, such as <, >, ', ", but ignores characters that may use to evade sanitization in Javascript contexts and result in XSS, such as \, \` and line breaks. Consider Razor as a safe sanitizer only when outputting dynamic data in an HTML context.
`
    },
    481: {
        risk: `
Code that reads from Session variables may trust them as server-side variables, but they may have been tainted by user inputs. This can lead to tampering with parameters used to authenticate or authorize users. Further, tainted Session variables offer an additional attack surface against the application - if untrusted data taints a Session variable, and that Session variable  is then used elsewhere without sanitization as if it were trusted, it could lead to further attacks such as Cross-Site Scripting, SQL Injection and more.`,
        cause: `
Server-side Session variables, or objects, are values assigned to a specific session, which is associated with a specific user. Often, they hold data relevant to that user's session, such as specific identifiers, user-type, authorization, authentication information and more. As such, the paradigm often associated to the Session object is that its contents can be trusted, as users cannot generally set these values themselves. 

The application places user input, which is untrusted data, in the server-side Session object, which is considered a trusted location. This could lead developers to treat untrusted data as trust`,
        recommendation: `
- Validate and sanitize all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

- Don’t mix untrusted user input with trusted data.`
    },
    495: {
        risk: `
Default error pages gives detailed information about the error that occurred, and should not be used in production environments.

Attackers can leverage the additional information provided by a default error page to mount attacks targeted on the framework, database, or other resources used by the application`,
        cause: ``,
        recommendation: `
- Handle exceptions appropriately in source code. The best practice is to use a custom error message. Make sure that the mode attribute is set to "RemoteOnly" in the web.config file as shown in the following example.
<customErrors mode="RemoteOnly" />

- The mode attribute of the <customErrors> tag in the Web.config file defines whether custom or default error pages are used. It should be configured to use a custom page as follows
<customErrors mode="On" defaultRedirect="YourErrorPage.htm" />

- Do not attempt to process an error or attempt to mask it.

- Verify return values are correct and do not supply sensitive information about the system.

- ASP .NET applications should be configured to use custom error pages instead of the framework default page.
`
    },
    496: {
        risk: `
Tests and debugging code are not intended to be deployed to the production environment, and can create unintended entry points, thus increasing the application's attack surface. Furthermore, this code is often not properly tested or maintained, and can retain historic vulnerabilities that were fixed in other parts of the codebase. Often, debug code will contain a functional "back door", by enabling the programmer to bypass operational security mechanisms, such as authentication or access controls.`,
        cause: `
During application development, it is common for programmers to implement specialized code, in order to ease debugging and testing. Often the programmer will even enable the debug code to bypass security mechanisms, so as to focus the tests on the specific functionality and isolate it from the security architecture. 

This debug or test code is not removed from the codebase, and is then included in the software build and deployed to the production environment.`,
        recommendation: `
- Remove all debug code before deploying or building the application. Ensure the configuration settings are not defined to enable debug mode. 

- Implement all test code via a dedicated test framework, which can isolate the test case code from the rest of the application. 

- Avoid implementing special "test code", "debugging-time" functionality, or "secret" interfaces or parameters in the application code itself. 

- Define and implement a standard and automatic build / deployment process, using dedicated CI / CD tools, that can automatically configure the deployed application, exclude all temporary code, and include only intended application code.
`
    },
    498: {
        risk: `
Cookies that contain the user's session identifier, and other sensitive application cookies, are typically accessible by client-side scripts, such as JavaScript. Unless the web application explicitly prevents this using the "httpOnly" cookie flag, these cookies could be read and accessed by malicious client scripts, such as Cross-Site Scripting (XSS). This flag would mitigate the damage done in case XSS vulnerabilities are discovered, according to Defense in Depth.`,
        cause: `
The web application framework, by default, does not set the "httpOnly" flag for the application's sessionid cookie and other sensitive application cookies. Likewise, the application does not explicitly use the "httpOnly" cookie flag, thus allowing client scripts to access the cookies by default.`,
        recommendation: `
- Always set the "httpOnly" flag for any sensitive server-side cookie.

- It is highly recommended to implement HTTP Strict Transport Security (HSTS) in order to ensure that the cookie will be sent over a secured channel.

- Configure the application to always use "httpOnly" cookies in the site-wide configuration file.

- Set the httpOnlyCookies attribute on the <httpCookies> element, under <system.web> in your application's web.config, to "true".`
    },
    500: {
        risk: `
Cookies that contain the user's session identifier, and other sensitive application cookies, should be sent to the server over a secure network communication (HTTPS) in order to prevent attackers from sniffing the traffic and stealing those cookies. Unless the web application explicitly prevents this by using the "secure" cookie flag, these cookies will also be sent over insecure traffic, which can lead to session hijacking and impersonation.`,
        cause: `
The web application framework by default does not set the "secure" flag for the application's sessionID cookie, and other sensitive application cookies. Likewise, the application does not explicitly use the "secure" cookie flag, allowing them to be sent in plaintext over an insecure session.`,
        recommendation: `
- Always set the "secure" flag for any sensitive server-side cookies.

- If the application explicitly handles cookies directly in application code, set the "secure" flag for sensitive cookies set by the application.
Secure-Code Approach

- Configure the application to always use "secure" cookies, in the site-wide configuration file.

- Enable the Secure flag or use the relevant Set-Secure API in the code.
`
    },
    501: {
        risk: `
Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.

The lack of proper session expiration may improve the likely success of certain attacks. For example, an attacker may intercept a session ID, possibly via a network sniffer or Cross-site Scripting attack. Although short session expiration times do not help if a stolen token is immediately used, they will protect against ongoing replaying of the session ID. In another scenario, a user might access a web site from a shared computer (such as at a library, Internet cafe, or open work environment). Insufficient Session Expiration could allow an attacker to use the browser's back button to access web pages previously accessed by the victim.
`,
        cause: ``,
        recommendation: `
Set sessions/credentials expiration date.
`
    },
    2126: {
        risk: `
Exposing the contents of a directory can lead to an attacker gaining access to source code or providing useful information for the attacker to devise exploits, such as creation times of files or any information that may be encoded in file names. The directory listing may also compromise private or confidential data`,
        cause: `
A directory listing provides an attacker with the complete index of all the resources located inside of the directory. The specific risks and consequences vary depending on which files are listed and accessible`,
        recommendation: `
Recommendations include restricting access to important directories or files by adopting a need to know requirement for both the document and server root, and turning off features such as Automatic Directory Listings that could expose private files and provide information that could be utilized by an attacker when formulating or conducting an attack.`
    },
    2226: {
        risk: `
Using a weak or broken algorithm ruins the protection granted by using cryptographic mechanisms in the first place, harming the confidentiality or integrity of sensitive user data. This could allow an attacker to steal secret information, alter sensitive data, or forge the source of modified messages.`,
        cause: `
The application code specifies the name of the selected cryptographic algorithm, either via a String argument, a factory method, or a specific implementation class. These algorithms have fatal cryptographic weaknesses, that make it trivial to break in a reasonable timeframe. Strong algorithms should withstand attacks far beyond the realm of possible.`,
        recommendation: `
- Only use strong, approved cryptographic algorithms, including AES, RSA, ECC, and SHA-256 respectively, amongst others. 

- Do not use weak algorithms that are considered completely broken, such as DES, RC4, and MD5, amongst others. 

- Avoid, where possible, using legacy algorithms that are not considered "future-proof" with sufficient safety margins, even though they are considered "safe enough" for today. This includes algorithms that are weaker than they should be, and have stronger replacements, even if they are not yet fatally broken - such as SHA-1, 3DES, 

- Consider using a relevant official set of classifications, such as NIST or ENISA. If possible, use only FIPS 140-2 certified algorithm implementations.`
    },
    2350: {
        risk: `
Cookies that contain the user's session identifier, and other sensitive application cookies, are typically accessible by client-side scripts, such as JavaScript. Unless the web application explicitly prevents this using the "httpOnly" cookie flag, these cookies could be read and accessed by malicious client scripts, such as Cross-Site Scripting (XSS). This flag would mitigate the damage done in case XSS vulnerabilities are discovered, according to Defense in Depth.`,
        cause: `
The web application framework, by default, does not set the "httpOnly" flag for the application's sessionid cookie and other sensitive application cookies. Likewise, the application does not explicitly use the "httpOnly" cookie flag, thus allowing client scripts to access the cookies by default.`,
        recommendation: `
- Always set the "httpOnly" flag for any sensitive server-side cookie.

- It is highly recommended to implement HTTP Strict Transport Security (HSTS) in order to ensure that the cookie will be sent over a secured channel.

- Explicitly set the "httpOnly" flag for each cookie set by the application.
       
- In particular, explicitly set the HttpCookie.HttpOnly property to true, for any cookie being added to the response. This includes any cookie implicitly being added to the response via the Response.Cookies collection property. 

- Preferably, configure the web application framework to automatically set httpOnly on all cookies, by setting the httpOnlyCookies attribute on the <httpCookies> element to "true", under <system.web> in your application's web.config.

- If the cookie is being written directly to the response headers, e.g. via the Response.AppendHeader() method with the "Set-Cookie" header name, append ";httpOnly;" to the end of the cookie value.
`
    },
    2405: {
        risk: `
Referencing deprecated modules can cause an application to be exposed to known vulnerabilities, that have been publicly reported and already fixed. A common attack technique is to scan applications for these known vulnerabilities, and then exploit the application through these deprecated versions. However, even if deprecated code is used in a way that is completely secure, its very use and inclusion in the code base would encourage developers to re-use the deprecated element in the future, potentially leaving the application vulnerable to attack, which is why deprecated code should be eliminated from the code-base as a matter of practice.

Note that the actual risk involved depends on the specifics of any known vulnerabilities in older versions.

Use of a deprecated API on client code may leave users vulnerable to browser-based attacks; this is exacerbated by the fact client-side code is available to any attacker with client access, who may be able to trivially detect use of this deprecated API.`,
        cause: `
The application references code elements that have been declared as deprecated. This could include classes, functions, methods, properties, modules, or obsolete library versions that are either out of date by version, or have been entirely deprecated. It is likely that the code that references the obsolete element was developed before it was declared as obsolete, and in the meantime the referenced code was updated.`,
        recommendation: `
- Always prefer to use the most updated versions of libraries, packages, and other dependencies.

- Do not use or reference any class, method, function, property, or other element that has been declared deprecated.`
    },
    2612: {
        risk: `
Clickjacking attacks allow an attacker to "hijack" a user's mouse clicks on a webpage, by invisibly framing the application, and superimposing it in front of a bogus site. When the user is convinced to click on the bogus website, e.g. on a link or a button, the user's mouse is actually clicking on the target webpage, despite being invisible. 

This could allow the attacker to craft an overlay that, when clicked, would lead the user to perform undesirable actions in the vulnerable application, e.g. enabling the user's webcam, deleting all the user's records, changing the user's settings, or causing clickfraud.`,
        cause: `
The root cause of vulnerability to a clickjacking attack, is that the application's web pages can be loaded into a frame of another website. The application does not implement a proper frame-busting script, that would prevent the page from being loaded into another frame. Note that there are many types of simplistic redirection scripts that still leave the application vulnerable to clickjacking techniques, and should not be used. 

When dealing with modern browsers, applications mitigate this vulnerability by issuing appropriate Content-Security-Policy or X-Frame-Options headers to indicate to the browser to disallow framing. However, many legacy browsers do not support this feature, and require a more manual approach by implementing a mitigation in Javascript. To ensure legacy support, a framebusting script is required.
`,
        recommendation: `
Generic Guidance:

    - Define and implement a a Content Security Policy (CSP) on the server side, including a frame-ancestors directive. Enforce the CSP on all relevant webpages. 
    
    - If certain webpages are required to be loaded into a frame, define a specific, whitelisted target URL. 
    
    - Alternatively, return a "X-Frame-Options" header on all HTTP responses. If it is necessary to allow a particular webpage to be loaded into a frame,  define a specific, whitelisted target URL. 
    
    - For legacy support, implement framebusting code using Javascript and CSS to ensure that, if a page is framed, it is never displayed, and attempt to navigate into the frame to prevent attack. Even if navigation fails, the page is not displayed and is therefore not interactive, mitigating potential clickjacking attacks.

Specific Recommendations:

    - Implement a proper framebuster script on the client, that is not vulnerable to frame-buster-busting attacks.
    
    - Code should first disable the UI, such that even if frame-busting is successfully evaded, the UI cannot be clicked. This can be done by setting the CSS value of the "display" attribute to "none" on either the "body" or "html" tags. This is done because, if a frame attempts to redirect and become the parent, the malicious parent can still prevent redirection via various techniques.
    
    - Code should then determine whether no framing occurs by comparing self === top; if the result is true, can the UI be enabled. If it is false, attempt to navigate away from the framing page by setting the top.location attribute to self.location.`
    },
    2719: {
        risk: `
A successful XSS exploit would allow an attacker to rewrite web pages and insert malicious scripts which would alter the intended output. This could include HTML fragments, CSS styling rules, arbitrary JavaScript, or references to third party code. An attacker could use this to steal users' passwords, collect personal data such as credit card details, provide false information, or run malware. From the victim’s point of view, this is performed by the genuine website, and the victim would blame the site for incurred damage.

An additional risk with DOM XSS is that, unlike reflected or stored XSS, tainted values do not have to go through the server. Since the server is not involved in sanitization of these inputs, server-side validation is not likely to not be aware XSS attacks have been occurring, and any server-side security solutions, such as a WAF, are likely to be ineffective in DOM XSS mitigation.
`,
        cause: `
The application creates web pages that include untrusted data, whether from user input, the application’s database, or from other external sources. The untrusted data is embedded directly in the page's HTML, causing the browser to display it as part of the web page. If the input includes HTML fragments or JavaScript, these are displayed too, and the user cannot tell that this is not the intended page. The vulnerability is the result of directly embedding arbitrary data without first encoding it in a format that would prevent the browser from treating it like HTML or code instead of plain text.

When a DOM XSS occurs, it is the client-side code itself that manipulates the local web-page's DOM, extracting data from some client-based storage, introducing potentially malicious content.`,
        recommendation: `
- Fully encode all dynamic data, regardless of source, before embedding it in output.

- Encoding should be context-sensitive. For example:

    - HTML encoding for HTML content
    - HTML Attribute encoding for data output to attribute values
    - JavaScript encoding for server-generated JavaScript

- It is recommended to use the platform-provided encoding functionality, or known security libraries for encoding output.

- Implement a Content Security Policy (CSP) with explicit whitelists for the application's resources only. 

- As an extra layer of protection, validate all untrusted data, regardless of source (note this is not a replacement for encoding). Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:
    - Data type
    - Size
    - Range
    - Format
    - Expected values

- In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page. 

- Set the HTTPOnly flag on the session cookie for "Defense in Depth", to prevent any successful XSS exploits from stealing the cookie.`
    },
    3018: {
        risk: `
The software stores a password in a configuration file that might be accessible to actors who do not know the password.

This can result in compromise of the system for which the password is used. An attacker could gain access to this file and learn the stored password or worse yet, change the password to one of their choosing.
`,
        cause: ``,
        recommendation: `
- Avoid storing passwords in easily accessible locations.

- Consider storing cryptographic hashes of passwords as an alternative to storing in plaintext.
`
    },
    3055: {
        risk: `Allowing setting of web-pages inside of a frame in an untrusted web-page will leave these web-pages vulnerable to Clickjacking, otherwise known as a redress attack. This may allow an attacker to redress a vulnerable web-page by setting it inside a frame within a malicious web-page. By crafting a convincing malicious web-page, the attacker can then use the overlayed redress to convince the user to click a certain area of the screen, unknowingly clicking inside the frame containing the vulnerable web-page, and thus performing actions within the user's context on the attacker's behalf.`,
        cause: `Failure to utilize the "X-FRAME-OPTIONS" header will likely allow attackers to perform Clickjacking attacks. Properly utilizing the "X-FRAME-OPTIONS" header would indicate to the browser to disallow embedding the web-page within a frame, mitigating this risk, if the browser supports this header. All modern browsers support this header by default.`,
        recommendation: `
- Utilize the "X-FRAME-OPTIONS" header flags according to business requirements to restrict browsers that support this header from allowing embedding web-pages in a frame:

- "X-Frame-Options: DENY" will indicate to the browser to disallow embedding any web-page inside a frame, including the current web-site.

- "X-Frame-Options: SAMEORIGIN" will indicate to the browser to disallow embedding any web-page inside a frame, excluding the current web-site.

- "X-Frame-Options: ALLOW-FROM https://example.com/" will indicate to the browser to disallow embedding any web-page inside a frame, excluding the web-site listed after the ALLOW-FROM parameter.`
    },
    3869: {
        risk: `
Value shadowing may result in an incorrect reference, such as one value being validated while a completely different one is used, or a value assumed to be safe (such as headers automatically issued by the browser, or server parameters) which can actually be overwritten by user inputs.`,
        cause: `
Value Shadowing occurs when a certain set of information can be searched and may contain values of the same name, whose precedence over one another is not immediately clear.

For example, in .NET, a Request object can be searched via an index (Request[param]) - however, the value whose key is "param" in this implementation may be a query string parameter, a form parameter, a header, a server variable and more. This causes the value of Request["value"] to be ambiguous, which could be leveraged for bypassing logic restrictions, security measures and value checks.
`,
        recommendation: `
Always explicitly refer to the exact data context from which values are retrieved.`
    },
    5312: {
        risk: `
Allowing the server to retain credentials may allow an attacker to retrieve them, and connect to the back-end using permissions associated to these credentials.`,
        cause: `
Setting Persist Security Info to TRUE allows security information, such username and password, to be obtained from a connection once it has been established. 

Setting it to False will make sure that security information is discarded after it is used to create the connection, reducing its exposure.`,
        recommendation: `
- Either explicitly set Persist Security Info to False, or leave it on its default value.

- If Persist Security Info is required to be True (e.g. for development purposes), it is vital to remove this flag or set it to False after it is no longer required.
`
    },
    5375: {
        risk: `
Failure to set an HSTS header and provide it with a reasonable "max-age" value of at least one year may leave users vulnerable to Man-in-the-Middle attacks.`,
        cause: `
Many users browse to websites by simply typing the domain name into the address bar, without the protocol prefix. The browser will automatically assume that the user's intended protocol is HTTP, instead of the encrypted HTTPS protocol.

When this initial request is made, an attacker can perform a Man-in-the-Middle attack and manipulate it to redirect users to a malicious web-site of the attacker's choosing. To protect the user from such an occurence, the HTTP Strict Transport Security (HSTS) header instructs the user's browser to disallow use of an unsecure HTTP connection to the the domain associated with the HSTS header.

Once a browser that supports the HSTS feature has visited a web-site and the header was set, it will no longer allow communicating with the domain over an HTTP connection.

Once an HSTS header was issued for a specific website, the browser is also instructed to prevent users from manually overriding and accepting an untrusted SSL certificate for as long as the "max-age" value still applies. The recommended "max-age" value is for at least one year in seconds, or 31536000.`,
        recommendation: `
- Before setting the HSTS header - consider the implications it may have:

    - Forcing HTTPS will prevent any future use of HTTP, which could hinder some testing

    - Disabling HSTS is not trivial, as once it is disabled on the site, it must also be disabled on the browser

- Set the HSTS header either explicitly within application code, or using web-server configurations.

- Ensure the "max-age" value for HSTS headers is set to 31536000 to ensure HSTS is strictly enforced for at least one year.

- Include the "includeSubDomains" to maximize HSTS coverage, and ensure HSTS is enforced on all sub-domains under the current domain

    Note that this may prevent secure browser access to any sub-domains that utilize HTTP; however, use of HTTP is very severe and highly discouraged, even for websites that do not contain any sensitive information, as their contents can still be tampered via Man-in-the-Middle attacks to phish users under the HTTP domain.

- Once HSTS has been enforced, submit the web-application's address to an HSTS preload list - this will ensure that, even if a client is accessing the web-application for the first time (implying HSTS has not yet been set by the web-application), a browser that respects the HSTS preload list would still treat the web-application as if it had already issued an HSTS header. Note that this requires the server to have a trusted SSL certificate, and issue an HSTS header with a maxAge of 1 year (31536000)

- Note that this query is designed to return one result per application. This means that if more than one vulnerable response without an HSTS header is identified, only the first identified instance of this issue will be highlighted as a result. If a misconfigured instance of HSTS is identified (has a short lifespan, or is missing the "includeSubDomains" flag), that result will be flagged. Since HSTS is required to be enforced across the entire application to be considered a secure deployment of HSTS functionality, fixing this issue only where the query highlights this result is likely to produce subsequent results in other sections of the application; therefore, when adding this header via code, ensure it is uniformly deployed across the entire application. If this header is added via configuration, ensure that this configuration applies to the entire application.

- Note that misconfigured HSTS headers that do not contain the recommended max-age value of at least one year or the "includeSubDomains" flag will still return a result for a missing HSTS header.
`
    },
    6406: {
        risk: `
It is often possible to retrieve and view the application source code. For web applications, it is even simpler to "View Source" in the user's browser. Thus, a malicious user can steal these passwords, and use them to impersonate whoever they belong to. It is not known if these are valid, current passwords, nor if they are user passwords or for backend systems, like a database.`,
        cause: `
A well-developed application will have it's source code well commented. Often, programmers will leave deployment information in comments, or retain debugging data that was used during development. These comments often contain secret data, such as passwords. These password comments are stored in the source code in perpetuity, and are not protected.`,
        recommendation: `
Do not store secrets, such as passwords, in source code comments.`
    },
    591: {
        risk: `
A successful XSS exploit would allow an attacker to rewrite web pages and insert malicious scripts which would alter the intended output. This could include HTML fragments, CSS styling rules, arbitrary JavaScript, or references to third party code. An attacker could use this to steal users' passwords, collect personal data such as credit card details, provide false information, or run malware. From the victim’s point of view, this is performed by the genuine website, and the victim would blame the site for incurred damage.

The attacker could use social engineering to cause the user to send the website modified input, which will be returned in the requested web page.
`,
        cause: `
The application creates web pages that include untrusted data, whether from user input, the application’s database, or from other external sources. The untrusted data is embedded directly in the page's HTML, causing the browser to display it as part of the web page. If the input includes HTML fragments or JavaScript, these are displayed too, and the user cannot tell that this is not the intended page. The vulnerability is the result of directly embedding arbitrary data without first encoding it in a format that would prevent the browser from treating it like HTML or code instead of plain text.

Note that an attacker can exploit this vulnerability either by modifying the URL, or by submitting malicious data in the user input or other request fields.
`,
        recommendation: `
- Fully encode all dynamic data, regardless of source, before embedding it in output.

- Encoding should be context-sensitive. For example:

    - HTML encoding for HTML content

    - HTML Attribute encoding for data output to attribute values

- JavaScript encoding for server-generated JavaScript

- It is recommended to use the platform-provided encoding functionality, or known security libraries for encoding output.

- Implement a Content Security Policy (CSP) with explicit whitelists for the application's resources only. 

- As an extra layer of protection, validate all untrusted data, regardless of source (note this is not a replacement for encoding). Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values

- In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page. 

- Set the HTTPOnly flag on the session cookie for "Defense in Depth", to prevent any successful XSS exploits from stealing the cookie.

Java:

Returning Data To Clients Without Encoding


protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    
    response.setContentType("text/html;charset=UTF-8");
      
  	PrintWriter out = response.getWriter();
  	String loc = request.getParameter("location");
  
  	out.println("<h1> Location: " + loc + "<h1>");
}


Returning Data to Clients After Encoding The User Input


// Using HtmlEscapers by Google Guava

protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    
    response.setContentType("text/html;charset=UTF-8");
      
  	PrintWriter out = response.getWriter();
  	String loc = request.getParameter("location");
  	String escapedLocation = HtmlEscapers.htmlEscaper().escape(loc);
  
  	out.println("<h1> Location: " + escapedLocation + "<h1>");
}

`
    },
    600: {
        risk: `
Unreleased resources can cause a drain of those available for system use, eventually causing general reliability and availability problems, such as performance degradation, process bloat, and system instability. If a resource leak can be intentionally exploited by an attacker, it may be possible to cause a widespread DoS (Denial of Service) attack. This might even expose sensitive information between unprivileged users, if the resource continues to retain data or user id between subsequent allocations.`,
        cause: `
The application code allocates resource objects, but does not ensure these are always closed and released in a timely manner. This can include database connections, file handles, network sockets, or any other resource that needs to be released. In some cases, these might be released - but only if everything works as planned; if there is any runtime exception during the normal course of system operations, resources start to leak. 

Note that even in managed-memory languages such as Java, these resources must be explicitly released. Many types of resource are not released even when the Garbage Collector runs; and even if the the object would eventually release the resource, we have no control over when the Garbage Collector does run.`,
        recommendation: `
- Always close and release all resources.

- Ensure resources are released (along with any other necessary cleanup) in a finally { } block. Do not close resources in a catch { } block, since this is not ensured to be called. 

- Explicitly call .close() on any instance of a class that implements the Closable or AutoClosable interfaces. 

- Alternatively, an even better solution is to use the try-with-resources idiom, in order to automatically close any defined AutoClosable instances.

Java:

Unreleased Database Connection


private MyObject getDataFromDb(int id)  {
	MyObject data = null;
  	Connection con = null;
  	try {
	   Connection con = DriverManager.getConnection(CONN_STRING);      	
       data = queryDb(con, id); 
	}
	catch ( SQLException e ) {
	   handleError(e);
	}
}  


Explicit Release of Database Connection


private MyObject getDataFromDb(int id)  {
	MyObject data = null;
  	Connection con = null;
  	try {
	  Connection con = DriverManager.getConnection(CONN_STRING);      	
      data = queryDb(con, id); 
	}
	catch ( SQLException e ) {
	  handleError(e);
	}
  	finally {
      if ((con != null) && (!con.isClosed())) { con.close(); }
    }
}  


Automatic Implicit Release Using Try-With-Resources


private MyObject getDataFromDb(int id)  {
	MyObject data = null;
  	Connection con = null;
  	try (Connection con = DriverManager.getConnection(CONN_STRING)) {
       data = queryDb(con, id); 
	}
	catch ( SQLException e ) {
	  handleError(e);
	}
}  

`
    },
    609: {
        risk: `
An attacker could engineer audit logs of security-sensitive actions and lay a false audit trail, potentially implicating an innocent user or hiding an incident.`,
        cause: `
The application writes audit logs upon security-sensitive actions. Since the audit log includes user input that is neither checked for data type validity nor subsequently sanitized, the input could contain false information made to look like legitimate audit log data
`,
        recommendation: `
- Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values

- Validation is not a replacement for encoding. Fully encode all dynamic data, regardless of source, before embedding it in logs.

- Use a secure logging mechanism.

Java:

User Input Affects Logging


protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
  
    String color = request.getParameter("color");
    logger.info("{} was picked", color);
  	if colorList.contains(color){
      // Handle Response
    }else{
      // Handle Response
    }
}


User Input Encoded Prior Logging


protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
  
    String color = request.getParameter("color");
  	cleanColor = color.replace('\t', '_').replace('\n', '_').replace('\r', '_');
    logger.info("{} was picked", cleanColor);
  	if colorList.contains(cleanColor){
      // Handle Response
    }else{
      // Handle Response
    }
}

`
    },
    622: {
        risk: `
Exposed details about the application’s environment, users, or associated data (for example, stack trace) could enable an attacker to find another flaw and help the attacker to mount an attack. This may also leak sensitive data, e.g. passwords or database fields.`,
        cause: `
The application handles exceptions in an insecure manner, including raw details directly in the error message. This could occur in various ways: by not handling the exception; printing it directly to the output or file; explicitly returning the exception object; or by configuration. These exception details may include sensitive information that could leak to the users due to the occurrence of the runtime error.
`,
        recommendation: `
- Do not expose exception data directly to the output or users, instead return an informative, generic error message. Log the exception details to a dedicated log mechanism. 

- Any method that could throw an exception should be wrapped in an exception handling block that:

- Explicitly handles expected exceptions.

- Includes a default solution to explicitly handle unexpected exceptions.

- Configure a global handler to prevent unhandled errors from leaving the application.

Java:

Handle Exception by Printing To Output


private void wrapCallToDB_Unsafe(HttpServletRequest request) throws ServletException, IOException {
	String paramValue = request.getParameter("Param");

	try {
	  callDbProc(paramValue);	
	} catch (SQLException ex) {
	  ex.printStackTrace();
	}
}


Write Exception Details to Log, Send Generic Error Message


private void wrapCallToDB_SafePrintToLog(HttpServletRequest request) throws ServletException, IOException {
	String paramValue = request.getParameter("Param");

	try {
	  callDbProc(paramValue);	
	} catch (SQLException ex) {
	  writeExceptionToLog(ex);
	  System.err.println("Database Error, see log for details");
	}
}

`
    },
    627: {
        risk: `
An attacker could compromise the browser's Same Origin Policy and violate a user's privacy, by manipulating the browser's History object in JavaScript. This could allow the attacker in certain situations to detect whether the user is logged in, track the user's activity, or infer the state of other conditional values. This may also enhance Cross Site Request Forgery (XSRF) attacks, by leaking the result of the initial attack.
`,
        cause: `
Modern browsers expose the user's browsing history to local JavaScript as a stack of previously visited URLs. While the browsers enforce a strict Same Origin Policy (SOP) to prevent pages from one website from reading visited URLs on other websites, the History object does leak the size of the history stack. Using only this information, in some situations the attacker can discover the results of certain checks the application server performs.

For example - if the application redirects an unauthenticated user to the login page, a script on another website can detect whether or not the user is logged in, by checking the length of the history object. This is done by first making a request to the page being redirected to (e.g. "/login"), then replacing that with a redirecting page that only redirects users if that user is not yet authenticated (e.g. "/profile") - if the length of history object remains the same, redirection has occurred back to the page being redirected to, and the history stack is not updated. If the history stack length is updated, that means the page did not redirect the user, causing the new page to be stored in the history stack.

This information leakage is enabled when the application redirects the user's browser based on the value of some condition, the state of the user's server-side session. e.g. whether the user is authenticated to the application, if the user has visited a certain page with specific parameters, or the value of some application data.

Note that this issue does not affect all browsers, and depends on the browser's implementation of Javascript's history object behavior.
`,
        recommendation: `
- Add the response header "X-Frame-Options: DENY" to all sensitive pages in the application, to protect against the IFrame version of XSHM in modern browser versions.

- Add a random value to all redirection URLs as a parameter to ensure that they are unique when inserted into the history stack

Java:

Example of code that leaks the variable state via browser history


If (!isAuthenticated)
    response.sendRedirect("Login.jsp");     


Example code that prevents history leakage via random token


if (request.getParameter("r") == null)
    response.sendRedirect("Login.jsp?r=" + (new Random()).nextInt());

If (!isAuthenticated)
    response.sendRedirect("Login.jsp?r=" + (new Random()).nextInt());

`
    },
    646: {
        risk: `
Code that reads from Session variables may trust them as server-side variables, but they may have been tainted by user inputs. This can lead to tampering with parameters used to authenticate or authorize users. Further, tainted Session variables offer an additional attack surface against the application - if untrusted data taints a Session variable, and that Session variable  is then used elsewhere without sanitization as if it were trusted, it could lead to further attacks such as Cross-Site Scripting, SQL Injection and more.
`,
        cause: `
Server-side Session variables, or objects, are values assigned to a specific session, which is associated with a specific user. Often, they hold data relevant to that user's session, such as specific identifiers, user-type, authorization, authentication information and more. As such, the paradigm often associated to the Session object is that its contents can be trusted, as users cannot generally set these values themselves. 

The application places user input, which is untrusted data, in the server-side Session object, which is considered a trusted location. This could lead developers to treat untrusted data as trusted.
`,
        recommendation: `
- Validate and sanitize all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values

- Don’t mix untrusted user input with trusted data.

Java:

Setting User Role by Relying on User Input, Allowing Users to Tamper Its Value and Elevate Their Privilege


public void doPost (HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
	HttpSession session = request.getSession();
	String username = request.getParameter("username");
	byte[] password = request.getParameter("password").getBytes();
	if (isAuthenticated(username, password)) {
      String role = request.getParameter("role"); // Role can be tampered by user
	  session.setAttribute("isAuthenticated",true);
	  session.setAttribute("role", role); 
	  // Render page //
	} else {
	  // Authentication error //
	}
}


Derive User Role from An Internal Mechanism Based On The Current User


public void doPost (HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
	HttpSession session = request.getSession();
	String username = request.getParameter("username");
	byte[] password = request.getParameter("password").getBytes();
	if (isAuthenticated(username, password)) {
      String role = getUserRole(username); // Role is not derived from user input, but some post authentication mechanism
	  session.setAttribute("isAuthenticated",true);
	  session.setAttribute("role", role);
	  // Render page //
	} else {
	  // Authentication error //
	}
}
`
    },
    1063: {
        risk: `
A successful XSS exploit would allow an attacker to rewrite web pages and insert malicious scripts which would alter the intended output. This could include HTML fragments, CSS styling rules, arbitrary JavaScript, or references to third party code. An attacker could use this to steal users' passwords, collect personal data such as credit card details, provide false information, or run malware. From the victim’s point of view, this is performed by the genuine website, and the victim would blame the site for incurred damage.

The attacker could use social engineering to cause the user to send the website modified input, which will be returned in the requested web page.
`,
        cause: `
The application creates web pages that include untrusted data, whether from user input, the application’s database, or from other external sources. The untrusted data is embedded directly in the page's HTML, causing the browser to display it as part of the web page. If the input includes HTML fragments or JavaScript, these are displayed too, and the user cannot tell that this is not the intended page. The vulnerability is the result of directly embedding arbitrary data without first encoding it in a format that would prevent the browser from treating it like HTML or code instead of plain text.

Note that an attacker can exploit this vulnerability either by modifying the URL, or by submitting malicious data in the user input or other request fields.
`,
        recommendation: `
- Fully encode all dynamic data, regardless of source, before embedding it in output.

- Encoding should be context-sensitive. For example:

- HTML encoding for HTML content

- HTML Attribute encoding for data output to attribute values

- JavaScript encoding for server-generated JavaScript

- It is recommended to use the platform-provided encoding functionality, or known security libraries for encoding output.

- Implement a Content Security Policy (CSP) with explicit whitelists for the application's resources only. 

- As an extra layer of protection, validate all untrusted data, regardless of source (note this is not a replacement for encoding). Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values

- In the Content-Type HTTP response header, explicitly define character encoding (charset) for the entire page. 

- Set the HTTPOnly flag on the session cookie for "Defense in Depth", to prevent any successful XSS exploits from stealing the cookie.

Java:

Returning Data To Clients Without Encoding


protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    
    response.setContentType("text/html;charset=UTF-8");
      
  	PrintWriter out = response.getWriter();
  	String loc = request.getParameter("location");
  
  	out.println("<h1> Location: " + loc + "<h1>");
}


Returning Data to Clients After Encoding The User Input


// Using HtmlEscapers by Google Guava

protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    
    response.setContentType("text/html;charset=UTF-8");
      
  	PrintWriter out = response.getWriter();
  	String loc = request.getParameter("location");
  	String escapedLocation = HtmlEscapers.htmlEscaper().escape(loc);
  
  	out.println("<h1> Location: " + escapedLocation + "<h1>");
}

`
    },
    1653: {
        risk: `
A cloned object can be created without using its constructor, but also without going through its clone method's logic. Objects created without logic or checks may result in unexpected behavior, bypass of logical checks and more, depending on implementation and object usage.
`,
        cause: `
Declaring an object that implements the Cloneable interface allows setting an explicit method of cloning a new object, while allowing developers to implement any additional logic or checks; this is particularly useful when a set of objects must adhere to certain constraints. For example, if a new object requires all of an existing object's properties, with the exception of a unique identifier, this type of logic can be implemented into the cloning method. However, this can be bypassed in code - if the cloneable object is inherited by a new object, the new type of object can trivially override clone(), overriding the parent class' clone() logic and cause completely unexpected behavior around this new object type.
`,
        recommendation: `
When defining a Cloneable object, always set its clone() method implementation to "final" to prevent any implementations or extensions of this object from overriding clone() and replacing its logic.

Java:

Class B Hijacks A Objects, Removing Their Clone Logic

public class A implements Cloneable {
   public Object clone() {
       A cloneObj;
       /* 	Clone this object into cloneObj
       Validate & enforce logic
       */
       return A;
   }
}

public class B extends A {
       public Object clone() {
       B cloneObj;
       /* 	Clone this object into cloneObj
       Completely bypasses A's super class logic  
       */
       return B;
   }
}


"Final" Prevents Re-Implementation of Clone Method, Preventing Hijack of Class A Objects

public class A implements Cloneable {
   public final Object clone() {
      A cloneObj;
      /* 	Clone this object into cloneObj
       Validate & enforce logic
      */
      return A;
   }
}

`
    },
    1661: {
        risk: `
Files with implicit or dangerous permissions may allow attackers to retrieve sensitive data from the contents of these files, tamper their contents or potentially execute them.
`,
        cause: `
A file or directory is created with dangerous permissions, either by setting these permissions explicitly or relying on unsafe default permissions.`,
        recommendation: `
- Always create files with permissions being set explicitly

- Never set dangerous permissions on files

- Always consider the principle of least privilege when determining who may read, write or execute a file, if these permissions are to be granted at all

Java:

Writing A File with Implicit Permissions

File tempFile = File.createTempFile(TEMP_FILE_PREFIX,TEMP_FILE_SUFFIX, new File(TEMP_FOLDER));
FileWriter fw = new FileWriter(tempFile);
fw.write(CONTENT);


Writing A File with Explicit Permissions

File tempFile = File.createTempFile(TEMP_FILE_PREFIX,TEMP_FILE_SUFFIX, new File(TEMP_FOLDER));
FileWriter fw = new FileWriter(tempFile);
tempFile.setExecutable(false);
tempFile.setReadable(true);
tempFile.setWritable(true);
fw.write(CONTENT);

`
    },
    1670: {
        risk: `
An attacker could define arbitrary file path for the application to use, potentially leading to:

- Stealing sensitive files, such as configuration or system files

- Overwriting files such as program binaries, configuration files, or system files

- Deleting critical files, causing denial of service (DoS).
`,
        cause: `
The application uses user input in the file path for accessing files on the application server’s local disk.
`,
        recommendation: `
- Ideally, avoid depending on dynamic data for file selection.

- Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values

- Accept dynamic data only for the filename, not for the path and folders.

- Ensure that file path is fully canonicalized.

- Explicitly limit the application to use a designated folder that is separate from the applications binary folder.
 
- Restrict the privileges of the application’s OS user to necessary files and folders. The application should not be able to write to the application binary folder, and should not read anything outside of the application folder and data folder.`
    },
    1699: {
        risk: `
An attacker could input a very high value, potentially causing a denial of service (DoS).
`,
        cause: `
The application performs some repetitive task in a loop, and defines the number of times to perform the loop according to user input. A very high value could cause the application to get stuck in the loop and to be unable to continue to other operations.
`,
        recommendation: `
Ideally, don’t base a loop on user-provided data. If it is necessary to do so, the user input must be first validated and its range should be limited.

Java:

Loop Condition Is Not Bounded By Any Value


protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

   int loopCount = 0;
   try{
       loopCount = Integer.parseInt(request.getParameter("loopCount"));
   } catch(NumberFormatException e){
       return DEFAULT_VAL;
   }
   for(int i=0; i < loopCount; i++){
       //Do Something
   }
}


Loop Condition is Bounded With MAX_LOOPS

protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

   int loopCount = 0;
   try{
       loopCount = Integer.parseInt(request.getParameter("loopCount"));
   } catch(NumberFormatException e){
       return DEFAULT_VAL;
   }
   if(loopCount > MAX_LOOPS){
       loopCount = MAX_LOOPS;
   }
   for(int i=0; i < loopCount; i++){
       //Do Something
   }
}
`
    },
    3618: {
        risk: `
An attacker could define arbitrary file path for the application to use, potentially leading to:

- Stealing sensitive files, such as configuration or system files

- Overwriting files such as program binaries, configuration files, or system files

- Deleting critical files, causing denial of service (DoS).`,
        cause: `
The application uses user input in the file path for accessing files on the application server’s local disk.
`,
        recommendation: `
- Ideally, avoid depending on dynamic data for file selection.

- Validate all input, regardless of source. Validation should be based on a whitelist: accept only data fitting a specified structure, rather than reject bad patterns. Check for:

    - Data type
    - Size
    - Range
    - Format
    - Expected values

- Accept dynamic data only for the filename, not for the path and folders.

- Ensure that file path is fully canonicalized.

- Explicitly limit the application to use a designated folder that is separate from the applications binary folder.

- Restrict the privileges of the application’s OS user to necessary files and folders. The application should not be able to write to the application binary folder, and should not read anything outside of the application folder and data folder.

Java:

Absolute Path Traversal in "filename" Parameter


private String getFileContents(HttpServletRequest request) throws ServletException, FileNotFoundException, IOException {
	String filename = request.getParameter("filename");
	Path path = Paths.get(filename);
	byte[] fileContentBytes = Files.readAllBytes(path);
	String fileContents = new String(fileContentBytes, FILE_CONTENT_ENCODING_STRING);
  	return fileContents;
}


Relative Path Traversal in "filename" Parameter


private String getFileContents(HttpServletRequest request) throws ServletException, FileNotFoundException, IOException {
	String filename = request.getParameter("filename");
	Path path = Paths.get(SERVED_FILES_DIR + filename);
	byte[] fileContentBytes = Files.readAllBytes(path);
	String fileContents = new String(fileContentBytes, FILE_CONTENT_ENCODING_STRING);
  	return fileContents;
}


Path Traversal Mitigate via Sanitization of Path Variable


private static String sanitizePathTraversal(String filename) {
  	Path p = Paths.get(filename);
  	return p.getFileName().toString();
}

private String getFileContents_fixed(HttpServletRequest request) throws ServletException, FileNotFoundException, IOException {
	String filename = sanitizePathTraversal(request.getParameter("filename")); // Ensures access only to files in a given folder, no traversal
	Path path = Paths.get(SERVED_FILES_DIR + filename);
	byte[] fileContentBytes = Files.readAllBytes(path);
	String fileContents = new String(fileContentBytes, FILE_CONTENT_ENCODING_STRING);
  	return fileContents;
}

`
    },
    3771: {
        risk: `
All variables stored by the application in unencrypted memory can potentially be retrieved by an unauthorized user, with privileged access to the machine. For example, a privileged attacker could attach a debugger to the running process, or retrieve the process's memory from the swapfile or crash dump file. Once the attacker finds the user passwords in memory, these can be reused to easily impersonate the user to the system.
`,
        cause: `
- String variables are immutable - in other words, once a string variable is assigned, its value cannot be changed or removed. Thus, these strings may remain around in memory, possibly in multiple locations, for an indefinite period of time until the garbage collector happens to remove it. Sensitive data, such as passwords, will remain exposed in memory as plaintext with no control over their lifetime.

- While it may still be possible to retrieve data from memory, even if it uses a mutable container that is cleared, or retrieve a decryption key and decrypt sensitive data from memory - layering sensitive data with these types of protection would significantly increase the required effort to do so. By setting a high bar for retrieving sensitive data from memory, and reducing the amount and exposure of sensitive data in memory, an adversary is significantly less likely to succeed in obtaining valuable data.
`,
        recommendation: `
When it comes to avoiding Heap Inspection, it is important to note that, given any read access to memory or a memory dump of an application, it is always likely to disclose some sensitive data to an adversary - these suggestions are part of defense-in-depth principles for protection of sensitive data in cases where such memory read access is successfully obtained. These recommendations will enable significant reduction in the lifespan and exposure of sensitive data in memory; however - given enough time, effort and unlimited access to memory, they will only go so far in protecting sensitive data being used by the application. The only way to handle Heap Inspection issues is to minimize and reduce data exposure, and obscure it in memory wherever possible.


- Do not store sensitive data, such as passwords or encryption keys, in memory in plain-text, even for a short period of time. 

- Prefer to use specialized classes that store encrypted data in memory to ensure it cannot be trivially retrieved from memory.

- When required to use sensitive data in its raw form, temporarily store it in mutable data types, such as byte arrays, to reduce readability from memory, and then promptly zeroize the memory locations, to reduce exposure duration of this data while in memory.

- Ensure that memory dumps are not exchanged with untrusted parties, as even by ensuring all of the above - it may still be possible to reverse-engineer encrypted containers, or retrieve bytes of sensitive data from memory and rebuild it.

- In Java, do not store passwords in immutable strings - prefer using an encrypted memory object, such as SealedObject.

Java:

Plaintext Password in Immutable String


class Heap_Inspection 
{
    private String password;
    
    public void setPassword(String password)
    {	
    this.password = password;
    }
}


Password Protected in Memory


class Heap_Inspection_Fixed 
{
    private SealedObject password;
    
    public void setPassword(Character[] input)
    {	
       Key key = getKeyFromConfiguration();
       Cipher c = Cipher.getInstance(CIPHER_NAME);
       c.init(Cipher.ENCRYPT_MODE, key);
       List<Character> characterList = Arrays.asList(input);
       password = new SealedObject((Serializable) characterList, c);
       Arrays.fill(input, '\\0'); // Zero out input. Will also overwrite the values in characterList by reference.
    }
}

`
    },
    3884: {
        risk: `
Files with implicit or dangerous permissions may allow attackers to retrieve sensitive data from the contents of these files, tamper their contents or potentially execute them.
`,
        cause: `
A file or directory is created with dangerous permissions, either by setting these permissions explicitly or relying on unsafe default permissions.`,
        recommendation: `
- Always create files with permissions being set explicitly

- Never set dangerous permissions on files

- Always consider the principle of least privilege when determining who may read, write or execute a file, if these permissions are to be granted at all

Java:

Writing A File with Implicit Permissions

File tempFile = File.createTempFile(TEMP_FILE_PREFIX,TEMP_FILE_SUFFIX, new File(TEMP_FOLDER));
FileWriter fw = new FileWriter(tempFile);
fw.write(CONTENT);


Writing A File with Explicit Permissions

File tempFile = File.createTempFile(TEMP_FILE_PREFIX,TEMP_FILE_SUFFIX, new File(TEMP_FOLDER));
FileWriter fw = new FileWriter(tempFile);
tempFile.setExecutable(false);
tempFile.setReadable(true);
tempFile.setWritable(true);
fw.write(CONTENT);

`
    },
    3890: {
        risk: `
Unauthorized actions may allow attackers to write malicious content or code to files, databases and other I\Os or read sensitive I\O contents. Impact of this issue varies, depending on implementation, but may allow:


- Remote code execution, in case an attacker is able to inject malicious data into a writable I\O, which would then be interpreted or compiled as code

- Overwriting or leaking of configuration files

- Compromising confidentiality or integrity of stored data
`,
        cause: `
A logic flow in code triggers I/O and is not authorized. If an attacker can trigger it, it may leave it vulnerable to attack.
`,
        recommendation: `
When logic flows are affected by user input or behavior, always ensure the user is authorized to trigger them.

Java:

Writing to File Without Any Authorization Checks


Part filePart = request.getPart("file");
if (filePart != null) {
	InputStream filecontent = null;
	filecontent = filePart.getInputStream();
	Path path = Paths.get(filename);
	byte[] contentByteArray = new byte[filecontent.available()];
	filecontent.read(contentByteArray);
	Files.write(path, contentByteArray);
}


Using a Basic Authorization Check Based on Session Variables


HttpSession session = request.getSession();
String role = (String)session.getAttribute("role");
if (role.equals(ADMIN)) {
	Part filePart = request.getPart("file");
	if (filePart != null) {
	   InputStream filecontent = null;
	   filecontent = filePart.getInputStream();
	   Path path = Paths.get(filename);
	   byte[] contentByteArray = new byte[filecontent.available()];
	   filecontent.read(contentByteArray);
	   Files.write(path, contentByteArray);
	}
}

`
    },
    3894: {
        risk: `
Allowing users to save files of unrestricted size may allow attackers to fill file storage with junk, or conduct long writing operations which would strain systems conducting the saving operation. Exhausting this storage space or constraining it to the point where it is unavailable will result in denial of service.
`,
        cause: `
Application code does not validate file size before saving files uploaded by users to storage, potentially allowing upload of files of any size.`,
        recommendation: `
Constrain intended file size in code to prevent attackers from uploading files of arbitrary sizes by performing size checks. Do not rely on client-side size checks or any size parameters provided by users; evaluate the size of the file on the server, instead.

Java:

public void saveMultipartFile(CommonsMultipartFile multipartFile, String path) throws IOException {
    FileOutputStream fos = new FileOutputStream(path);
    fos.write(multipartFile.getBytes());
    fos.close();
}



public void saveMultipartFile(CommonsMultipartFile multipartFile, String path) throws IOException {
    if (multipartFile.getSize() < MAX_SIZE) {
       FileOutputStream fos = new FileOutputStream(path);
       fos.write(multipartFile.getBytes());
       fos.close();
    } else {
       throw new IOException("Maximum file size exceeded!");
    }
}

`
    },
    4446: {
        risk: `
Performing string manipulations and comparisons without regard to the locale, can result in unexpected results. This can lead to bypass of input validation, format string attacks, 

and possibly other string-based attacks such as Cross-Site Scripting (XSS), SQL Injection, and even Denial of Service (DoS).`,
        cause: `
Many classes and methods perform locale-sensitive operations, including formatting numbers, dates, and strings according to the specific language and region. Many of these methods 

allow the caller to ignore the locale or character set, and apply formatting and language rules based on the default locale settings for the current environment. 
       
However, depending on the default settings, this could result in unexpected results. As an example, using the Turkish locale to transform a string to uppercase will turn a lowercase "i" into "LATIN CAPITAL LETTER I WITH DOT ABOVE" (Unicode codepoint 0130). Clearly, this is not the expected result, and a comparison with a proper uppercase "I" would fail.
`,
        recommendation: `
- Always use locale-sensitive functions for comparing and manipulating specific strings, that are intended to have a particular value. 

- In Java, prefer to use the Locale.ROOT locale as a neutral locale.

Java:

Locale Ignorant String Comparison


private bool validateInput(String input) {
    if (input.toUpperCase().indexOf("SCRIPT") < 0)
       return true;    // Input string does not contain any form of SCRIPT
    else
       return false;
}


Locale-Neutral String Comparison


private bool validateInput(String input) {
    if (input.toUpperCase(Locale.ROOT).indexOf("SCRIPT") < 0)
       return true;    // Input string does not contain any form of SCRIPT
    else
       return false;
}
`
    },
    4505: {
        risk: `
An unsuspecting user might click a vulnerable legitimate-looking link, prepared by an attacker, that leads to a malicious page. The new page that opens can redirect the original page to another malicious page and abuse the trust of the user to create a very convincing phishing attack.
`,
        cause: `
When opening a new page using an  HTML element with the "target" attribute (with any value), or with window.open() within JavaScript, the new page has some access to the original page through the window.opener object. This may allow redirection to a malicious phishing page.
`,
        recommendation: `
For HTML:

- Do not set the "target" attribute (with any value) for links created by users unless required.   

- If required, when using the "target" attribute, also set the "rel" attribute as “noopener noreferrer”:

    - “noopener” for Chrome and Opera
    - “noreferrer” for Firefox and old browsers
    - No similar solution for Safari


For JavaScript:

- When invoking an untrusted new window using "var newWindow = window.open()", set "newWindow.opener=null" before setting "newWindow.location" to a potentially untrusted site, such that when the new site is open in the new window, it has no access to its original "opener" attribute
`
    },
    6372: {
        risk: `
Sending sensitive information in a GET parameter as part of the URL's query string will result in this information potentially becoming cached by the browser, proxies, web-caches or be written into access logs. An attacker with access to any of the above will be able to retrieve this sensitive information.
`,
        cause: `
A password is being sent in a GET request as a query string parameter, either via concatenation of the password value to a URL, or by sending the password as a parameter in a GET request.  Sending parameters in a GET request is caused either by explicitly setting the method to GET, or implicitly by using a mechanism that defaults to a GET request without changing the method to another method (such as POST).
`,
        recommendation: `
Never send sensitive information in the URL. This includes:

    - Credentials
    - Session or access tokens
    - Personal information

    Java:

Receiving an access token through GET method.


protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    PrintWriter out = response.getWriter();
    String temp = request.getParameter("secret_token");
    if (temp==null) { out.print("Unauthorized");} 
    else {
       out.print("<html><body><h1 align='center'>" + new Date().toString() + "</h1></body></html>");
    }
}


Receiving an access token through POST method.


protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    PrintWriter out = response.getWriter();
    String temp = request.getParameter("secret_token");

    if (temp==null) {
       out.print("Unauthorized");
    }else{
       out.print("<html><body><h1 align='center'>" +
       new Date().toString() + "</h1></body></html>");
    }
}

`
    },
    6382: {
        risk: `
APIs often respond with objects for a client to consume and, at times, these objects may contain more information than the client requires or intends to use. If the object returned to the client has this excess data, and that data is sensitive, it would be exposed to potentially malicious clients of the API.
`,
        cause: `
The API returns an object with potentially sensitive data-fields, without excluding, filtering or nullifying said sensitive data - thus exposing it in an API response.
`,
        recommendation: `
- When returning objects that hold data from an API, always consider the types and contexts of data being returned - such as whether or not it is required by the API's consumers, and whether or not it is sensitive

- Opt to white-list allowed data to be in control of data flow and remove excess

Java

Exposing a Sensitive Field in a Spring REST API Response


// POJO with Sensitive Data
@Entity
public class User {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    // Field will be exposed if User object is returned as-is from API:
    private String encryptedPassword; 
    // ... public constructors getters and setters ... //
}

// Spring REST Controller Mapped Method
@GetMapping("/users/{id}")
User findOne(@PathVariable Long id) {
    User user = repository.findById(id).orElseThrow(() -> new UserNotFoundException(id));
    return user;
}


Using a DTO and ModelMapper To Whitelist Desired Output Fields in a Spring REST API


// POJO with Sensitive Data
@Entity
public class User {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    private String encryptedPassword; 
    // ... public constructors getters and setters ... //
}

// DTO without Sensitive Data
public class UserDTO {
    private Long id;
    private String username;
    // ... public constructors getters and setters ... //
}

// Spring REST Controller Mapped Method
@GetMapping("/users/{id}")
User findOne(@PathVariable Long id) {
    User user = repository.findById(id).orElseThrow(() -> new UserNotFoundException(id));
    UserDTO userDTO = modelMapper.map(user, UserDTO.class);
    return userDTO;
}


Spring Annotation Used to Exclude A Field from JSON Entirely - Can Also Be Set on Getter Individually to Allow Setting a Value While Preventing Exposure


// POJO with Sensitive Data
@Entity
public class User {
    @Id
    @GeneratedValue
    private Long id;
    private String username;
    @JsonIgnore
    private String encryptedPassword; 
    // ... public constructors getters and setters ... //
}

`
    },
    6430: {
        risk: `
A Cross-Origin Resource Sharing (CORS) header, "Access-Control-Allow-Origin", that is overly permissive may allow scripts from other web-sites to access, and often manipulate, resources on the affected web-application. These resources may include page contents, tokens and more, allowing potential Cross-Site Request Forgery (CSRF) or Cross-Site Scripting (XSS) attacks, performing actions on a user's behalf such as changing their password, or allow breach of user privacy.
`,
        cause: `
Modern browsers, by default, disallow resource sharing between different domains from accessing one another's DOM contents, cookie jars and other resources, specifically to prevent malicious web-applications from attacking legitimate web-applications and their users as part of the Same-Origin Policy (SOP). For example - website A cannot retrieve contents of website B by default, as that is a breach of the SOP. The Cross-Origin Resource Sharing (CORS) policy, defined by specific headers, allows loosening this strict default behavior to enable cross-site communications. However, when used incorrectly, CORS may enable unintended and potentially malicious behavior by allowing an overly broad trust of web-applications that may submit requests and retrieve responses from the web-application.

The Access-Control-Allow-Origin is incorrectly set to an unsafe value in code.`,
        recommendation: `
Where not explicitly required, do not set any CORS headers. Where required, consider business needs for setting these headers, and opt for the most restrictive configuration possible, such as white-listing trusted, secure and allowed domains access, while utilizing other CORS headers to strictly provide required and expected functionality.

Spring Security has a built-in mechanism to configure the CORS header using the @CrossOrigin annotation.

Spring's default allowed origin is overly permissive and it is recommended to manually specify the allowed origins.

Java:

Default 'origins' Parameter Allowing All Origins in a Specific Endpoint


@RestController
@RequestMapping("/resource")
public class ResourceController {

	@CrossOrigin
	@GetMapping("/{id}")
	public Resource retrieve(@PathVariable Long id) {
	   //  ...
	}
}


Setting an 'origins' Parameter on a Specific Controller


@CrossOrigin(origins = "https://example.com", maxAge = 3600)
@RestController
@RequestMapping("/resource")
public class ResourceController {

	@GetMapping("/{id}")
	public Resource retrieve(@PathVariable Long id) {
	 //  ...
	}
}


Applying the CORS Header to Every Endpoint Using Spring Security's Java Configuration


@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
     http
	 // by default uses a Bean by the name of corsConfigurationSource
	 .cors();
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
	    CorsConfiguration configuration = new CorsConfiguration();
	    configuration.setAllowedOrigins(Arrays.asList("https://example.com"));
	    configuration.setAllowedMethods(Arrays.asList("GET","POST"));
	    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
// Applying the CORS to all endpoints
source.registerCorsConfiguration("/**", configuration);
	    return source;
	}
}


Wildcard Access-Control-Allow-Origin


response.addHeader("Access-Control-Allow-Origin", "*");


Access-Control-Allow-Origin Being Set for a Trusted Domain


// Assuming https://www.example.com is a trusted domain
response.addHeader("Access-Control-Allow-Origin", "https://www.example.com");


Dynamically Determine Access-Control-Allow-Origin from Origin Header


String origin = request.getHeader("Origin");
response.addHeader("Access-Control-Allow-Origin", origin);


XML:

Applying Spring Security's Default CORS with an Overly Permissive Configuration


<http>
	<cors />
</http>

`
    },
    6446: {
        risk: `
The Content-Security-Policy header enforces that the source of content, such as the origin of a script, embedded (child) frame, embedding (parent) frame or image, are trusted and allowed by the current web-page; if, within the web-page, a content's source does not adhere to a strict Content Security Policy, it is promptly rejected by the browser. Failure to define a policy may leave the application's users exposed to Cross-Site Scripting (XSS) attacks, Clickjacking attacks, content forgery and more.
`,
        cause: `
The Content-Security-Policy header is used by modern browsers as an indicator for trusted sources of content, including media, images, scripts, frames and more. If these policies are not explicitly defined, default browser behavior would allow untrusted content.

The application creates web responses, but does not properly set a Content-Security-Policy header.
`,
        recommendation: `
Explicitly set the Content-Security-Policy headers for all applicable policy types (frame, script, form, script, media, img etc.) according to business requirements and deployment layout of external file hosting services. Specifically, do not use a wildcard, '*', to specify these policies, as this would allow content from any external resource.

The Content-Security-Policy can be explicitly defined within web-application code, as a header managed by web-server configurations, or within <meta> tags in the HTML <head> section.

Java

Adding CSP Header Using Spring Security Java Configuration


@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
       // Add CSP headers
       http.headers().contentSecurityPolicy("script-src 'self' https://example.com; object-src https://example.com; report-uri /csp-report-endpoint/");
    }
}


HTTP Response With CSP Header Set


protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    // handle request
    response.setHeader("Content-Security-Policy", "default-src 'self'"); // default-src is the most restric mode of CSP and covers all applicable policy types
}


HTTP Response with CSP Header in Spring


@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
    .headers()
    .contentSecurityPolicy("default-src 'self'"); // default-src is the most restric mode of CSP and covers all applicable policy types
    }
}


XML

Adding CSP Header Using Spring Security XML Configuration


<http>
    <!-- ... -->

    <headers>
    <content-security-policy policy-directives="script-src 'self' https://apis.example.com">
       </content-security-policy>
    </headers>
</http>

`
    },
    6448: {
        risk: `
Failure to set an Expect-CT header and provide it with the "enforce" parameter and a reasonable "max-age" value of at least one year may leave users vulnerable to Man-in-the-Middle attacks.
`,
        cause: `
When using SSL/TLS, browsers validate the certificate sent by the server during the connection's handshake against the client's list of recognized CAs (Certificate Authorities). This model's security transfers the trust from the server to the CA.

Declaring Expect-CT header makes the supported browsers use Certificate Transparency in order to detect compromises the CAs integrity and, as defined in the header parameters, to report and/or enforce a secure connection.

Using Certificate Transparency with Expect-CT and the right parameters, it's possible to avoid Man-in-the-Middle attacks.
`,
        recommendation: `
- Before setting the Expect-CT header - consider the implications it may have:

    - Enforcing Expect-CT will prevent any future use of HTTP, which could hinder some testing

    - Disabling Expect-CT is not trivial, as once it is disabled on the site, it must also be disabled on the browser

- Test your environment by setting the Expect-CT header without the 'enforce' flag in order to check if there are certificate issues - then use the 'enforce' flag

- Set the Expect-CT header either explicitly within application code, or using web-server configurations.

- Ensure the "max-age" value for Expect-CT headers is set to 31536000 to ensure the use of Certificate Transparency is strictly enforced for at least one year.

- If this header is added via configuration, ensure that this configuration applies to the entire application.

By default, Spring Security doesn't add this header.

XML:

Adding Expect_CT Header Using Spring Security's XML Configuration


<http>
  <headers>
    <header name="Expect-CT" value="max-age=3600, enforce"/>
  </headers>
</http>


Java:

Adding Expect_CT Header Using Spring Security's Java Configuration


@EnableWebSecurity
public class WebSecurityConfig extends
WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
	  // ...
	  .headers()
	  .addHeaderWriter(new StaticHeadersWriter("Expect-CT","max-age=3600, enforce"));
}


Setting a Header Using Java Filters


@Override
public void doFilter(ServletRequest request, ServletResponse response, FilterChain fchain) throws IOException, ServletException {
    HttpServletResponse httpResponse = ((HttpServletResponse) response);
    httpResponse.setHeader("Expect-CT", "max-age=3600, enforce");
    
    fchain.doFilter(request, response);
}
`
    },
}