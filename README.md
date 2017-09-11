# oss-lib-security

## 概述
> lib-security为了方便应用对资源的权限控制而生,基于spring-security,做了很多功能增强和自动化配置，来简化应用对spring-security的集成成本，使开发者很快的将权限控制的功能集成到自己的应用中。 

## 环境依赖

#### 配置JCE

    curl -s -k -L -C - -b "oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jce/8/jce_policy-8.zip > /tmp/policy.zip
    sudo sh -c "unzip -p /tmp/policy.zip UnlimitedJCEPolicyJDK8/local_policy.jar > ${JAVA_HOME}/jre/lib/security/local_policy.jar"
    sudo sh -c "unzip -p /tmp/policy.zip UnlimitedJCEPolicyJDK8/US_export_policy.jar > ${JAVA_HOME}/jre/lib/security/US_export_policy.jar"

#### 配置Maven依赖
- 项目需要先引入oss-release,然后使用如下方式引入lib-security。

    <dependency>
        <groupId>cn.home1</groupId>
        <artifactId>oss-lib-security-spring-boot-${spring-boot.version}</artifactId>
    </dependency>

- 使用lib-security，需要指定`spring-boot.version`,目前支持的springboot版本如下,
- 后续会随着springboot的演进，持续加入对新版springboot的支持。（这里推荐使用1.4.1）

    + 1.4.1.RELEASE
    + 1.4.2.RELEASE
  
> 为方便测试，可以加入`spring-security-test`的依赖。

    <dependency>
        <groupId>org.springframework.security</groupId>
        <artifactId>spring-security-test</artifactId>
        <scope>test</scope>
    </dependency>

# oss-lib-security  

## Features

#### App types

  Support 4 app types.  

> MIXED: RESTful API and template pages, with all authentication method.  
> RESOURCE: RESTful resource application with token and oauth authentication method only.  
> RESTFUL: RESTful application, no template pages, with all authentication method.  
> TEMPLATE: Template based application, no RESTful API, with all authentication method.

#### Error handle

  Integrated with oss-lib-errorhandle.  
  Standard error info.  

#### Secure cookie

  AES based encrypted cookie. For this, yml definition ex: 
  > app.security.cookieKey: 'AES256_CBC16:YDD7uVFNpvkId8HWI6xTfOeRW3O6Wk3FDuGJdnGDhiD='

#### Form auth

  An auth mechanism that carrying auth info by `application/x-www-form-urlencoded` form fields.  

  > app.security.loginPage : '/login.do'
  > app.security.loginProcessingUrl: '/login'
  > app.security.logoutUrl: '/logout'
	    
  Test with command line tool. TODO  

#### RSA password encryption

  Generate RSA keypair for password encryption. loginkey for Rsa pair key and loginPublicKeyUrl for client get rsaPublicKey.   

  > app.security.loginKey: 'RSA1024_PAIR_PKCS1_X509:MIICWwIBAAKBgQCRXunHa+5hw+L39UZoIFhPwPR9gBvdlEvlXAH4biP+GNb8OH77OjMsfjfs3dXs3QqwXMajJUKZFpX1v+w/ilZ9muvty4/wfQlx5qy305Ui6mRqpIQKKxkwgAS+LTVCh+AeFWfB9G/OVA/khp73VQ3/IPoqgcPG+e/RD/kdFwTozwIDAQABAoGAALbYqzQqjaxqtxErcWOHS40FJoC0olgSL2ROViwkXSE+HSsh5JYankNYfv9wB6PmY4txJmgOdbYYsoZo4L8LQbzV02cEzAibAltvS8JUZ0XWNbnhRnSvY+GJ24hf1BHIJGjBnkQDK/XrDw8Xzt2bSDlWyWH4iEC7PgpghQpHRZECQQDB1GK0U3iDofSJkdLpypxWE6T6MBl7RJCOROj56cXIaVcamOKD1D+x+aDrP7wH2Crhn5X83cTDGekDEIzs0tHjAkEAv/+A4QP61ZgEKn+1gk7RHw/tWHBLWhb1EcIpShBNWx8sB4G8wI7brf858iLXl9NhROkcqYmbchG3D6SnYZmRJQJAR8kxBTgk2huRRaIMSyoO3JJJ95740P6Dyy0aW/SIm8Dn0aHtwoVJUdDyGC5ypTUaLJW+Jvi7dsaR1eC7ULqDoQJAHoSNRrbsOuEz4FF2V2URxl8wubr3rzUw9Qaoq3YV5aL5y6OqjeznLCwCWOOC40YdEuf+v0/5HlOEhn8Ef/X55QJAKktna3oDVsfsTH6REVLz8kjvhILJ5yk493/yjTZxpcpcVv8LGjuCKtIn3NdCRoeIC1K+oLzbBB6U+J8Uu5aeSA==:MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRXunHa+5hw+L39UZoIFhPwPR9gBvdlEvlXAH4biP+GNb8OH77OjMsfjfs3dXs3QqwXMajJUKZFpX1v+w/ilZ9muvty4/wfQlx5qy305Ui6mRqpIQKKxkwgAS+LTVCh+AeFWfB9G/OVA/khp73VQ3/IPoqgcPG+e/RD/kdFwTozwIDAQAB'
  > app.security.loginPublicKeyUrl: '/login/rsaPublicKey'                              	    
  Test with command line tool. TODO

#### Verify code support

  Application needs to provide a *cn.home1.oss.lib.security.api.VerifyCodeProvider* implementation.

    app.security.verifyCode: true

  Test with command line tool. TODO  
  
## Integration

#### User and extended properties

  Application needs to implements *cn.home1.oss.lib.security.api.User*
  and provide extended properties by *public Map&lt;String, Object&gt; getProperties()* method.  

#### Role

  Role represents a group of users has the same privileges.  

  User ..M:N .. Role  
  
  User should provide *org.springframework.security.core.GrantedAuthority* implementations.  
  (by extends `cn.home1.oss.lib.security.api.AbstractRole`)
  Authority name should start with "ROLE_" (*cn.home1.oss.lib.security.api.Security.ROLE_PREFIX*).

#### Privilege

  Privilege represents an action to a resource.  

  Role ..M:N .. Privilege  
  
  User should provide *cn.home1.oss.lib.security.api.StaticPrivilege* implementations.  
  Privilege name should start with "PRIVILEGE_" (*cn.home1.oss.lib.security.api.StaticPrivilege.PRIVILEGE_PREFIX*).

#### (Default) Test users

  User should provide all test users by override cn.home1.oss.lib.security.api.BaseUserDetailsAuthenticationProvider&lt;T&gt;#protected List&lt;T&gt; testUsers().  

    app.security.defaultTestUser:'test_user'

## Basic auth

  An auth per request mechanism that carrying base64 auth info by request header.  
  Should be used with https.  
  
  Test with command line tool. TODO `curl -i -X GET -L http://test_user:user_pass@127.0.0.1:8080/users/current`

## Digest auth

  An auth per request mechanism that carrying password hashed auth info by request header.  
  Should be used with https.  
  
  Test with command line tool. TODO  

## UI / Front-end development

  Get user info. TODO  
  Request RSA public key for password encryption. TODO  
  Form auth. TODO  
  Basic auth.  TODO  
  Digest auth.  TODO  

## App security properties

    app:
      type:TEMPLATE					# 类型，可选的值为 MIXED|TEMPLATE|RESTFUL|RESOURCE 
      security:
        basePath: '/auth'            # auth相关的url前缀，下面相关的url默认都会拼接此前缀，默认是 /auth
        jwtKey: 'keySpec:value'      # 对jwt进行签名计算用的key
        permited: '/permited/**,/img/*' # 无须认证授权的url,多个用,隔开

    app.security.enabled=true # true | false, TODO 涉及哪些功能的开关
    app.security.cookieKey='keySpec:value' # AES key for encrypt / decrypt cookie, TODO 如何获得, 格式
    # auto generate auth token of defaultTestUser
    app.security.defaultTestUser= # default test user's name, see: cn.home1.oss.lib.security.api.BaseUserDetailsAuthenticationProvider .

#### Form login properties
    
    app.security.authEntryPoint=restful # restful | 403 | 401 | template (loginPage), TODO 何时用handler, 何时用entryPoint  
    app.security.authFailureHandler=restful # restful | template (loginPage), handler on auth failed.  
    app.security.authSucessHandler=restful # restful | template, handler on auth succeed. TODO test this
    app.security.loginKey='keySpec:value' # RSA key pair for encrypt password form field. TODO 如何获得, 格式  
    app.security.loginPublicKeyUrl=/api/login/publicKey # URL for RSA public key, TODO 如何获得, 格式
    app.security.loginPage=/login # custom login page TODO test this in different app types
    app.security.loginProcessingUrl=/api/login # URL for login form POST request.  
    app.security.logoutUrl=/api/logout # URL for logout request.  
    app.security.verifyCode=false # true | false, enable verifyCode or not. User needs to provide cn.home1.oss.lib.security.api.VerifyCodeProvider if enabled.  

## Used spring-boot properties
    
    security.ignored= # 
    security.basic.realm=Spring # 

## Customer Filter

| Filter        | Description | Ex  |
| ------------- |:-------------:| -----:|
|PermitedRequestConfiguration|for some request without auth|/img,/js| 
|CsrfConfiguration |generate XSRF-TOKEN||
|FormAuthConfiguration|for ||
|BasicAuthConfiguration| security basic auth||
|PreAuthConfiguration |fot cookie or token||

## RPC

  TODO  

## Debug

    org.springframework.security.web.FilterChainProxy#doFilterInternal
    
    ...
    private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    ...
        if (filters == null || filters.size() == 0) {
    ...
    see: this.filterChains

    org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
    
    ...
    public Collection<ConfigAttribute> getAttributes(Object object) {
    ...
        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : requestMap
        				.entrySet()) {
    ...
    see: this.requestMap

# RestFul应用接入lib-security

## 简介
> RestFul方式下，我们约定大部分的接口都是RestFul接口，但是不限制全部接口都必须是Restful接口，允许Template方式的接口存在。

##### application.yml配置

    app:
      security:RestFul
        enabled: true                # 是否启用
        basePath: '/auth'            # auth相关的url前缀，下面相关的url默认都会拼接此前缀，默认是 /auth
        loginProcessingUrl: '/login' # form表单提交的用户登录url，默认是 /login
        logoutUrl: '/logout'         # 用户登出的url，默认是 /logout
        loginPublicKeyUrl: /login/publicKey # 获取RSA公钥的url，默认是 /login/publicKey
        defaultTestUser: test_user   # 默认测试用户
        cookieKey: 'keySpec:value'   # 对cookie进行aes加密计算用的key
        jwtKey: 'keySpec:value'      # 对jwt进行签名计算用的key

- 用户模型
> 继承`cn.home1.oss.lib.security.api.AbstractUser`类并实现父类抽象方法，按需覆写父类方法。关于额外的用户信息，可以通过扩展`public Map<String, Object> 
getProperties()`来实现 

- service实现
    + `cn.home1.oss.lib.security.api.BaseUserDetailsAuthenticationProvider`类已经实现了`UserDetailsService`接口并hook了`ContextRefreshedEvent`事件。
    + lib-security不假定用户的存储逻辑，用户只需重写 findByName、save、delete等方法即可。
	
> 可以重写该类的 testUsers 方法，生成测试用户方便测试。
> lib-security配置中的defaultTestUser属性需要配合该方法使用，测试用户必须在用户提供的测试用户列表中进行选择。系统启动时，会将测试用户插入到持久化存储或内存中，具体依赖于用户实现的`UserDetailsService`中的`save(final User user)` 方法，自定义tsetUser方法如下:
	
    @Override
    protected List<User> testUsers() {
        return ImmutableList.of(
        User.userBuilder().email("user@somedomain.com").enabled(true) //
            .name("test_user").password("user_pass") //
            .roles(ImmutableSet.of(UserRole.ROLE_USER_AUTHORITY)) //
            .build(),
        User.userBuilder().email("admin@somedomain.com").enabled(true) //
            .name("test_admin").password("admin_pass") //
            .roles(ImmutableSet.of(UserRole.ROLE_ADMIN_AUTHORITY)) //
            .build());
    }

- 测试登录

    
    curl -i -X POST -L -c COOKIE --data "username=test_user&password=user_pass" http://127.0.0.1:8080:8080/auth/login
    
    Response:
    
    HTTP/1.1 200 OK
    Date: Mon, 12 Dec 2016 07:01:36 GMT
    Set-Cookie: generic_user=QPBhNLLca0YvYt0l29hFCP1foCi8ca2FPy7uk0On80TlEY5%2BqUasIzEp6rjc7crxahUJIdbGig9f66iyf2WbpVGTxFwY44hA04Gz6Z4M77P9fhNYyYx7XrUh8BC1J8l%2Fx0FIcxaQ5ASwNB%2FVSu00xJh8%2BizCYvdXBumKckzrclXrEvDlvhkAZzo4jWgm%2BsrbpUDA13S1GzfspG9fOzMBaZ7ais2NsHq%2FWL49NOzMcHXxJKruHeK7jIUk%2B1KNv5RpDZ%2BKtBAWysWKjvgTG%2B3xgbGRjWArCQZwi2YK2AY1Pj6MDeRfdEsdUwY%2F%2B3GejqWAdhYIvQMKJFEZ4KDzJXeX5wqYuYC%2FkwxnVG1hCrIQr7IUoOkXGUMRXoAvtMRKVTLD2creOLCbvDM3ig2%2F3VxYBxyCG0nrwHpkzmDe33E0JpQb1v0hxvYhnC7yRAQwUIYiiVoGRKaK9dAuYtAJIDKDM33R3%2FbZkpN%2Bt7on5%2FEDFwh3qkWVif3F0Iy%2FquyAsQKm2QZ7v5Iiod9EVwEcK3hy%2FoXr6Z874Zg%2B8vtr9EZ4QvYucxHren1apojB0NFCxIuUBvIEX0dZd4qNQsITFWi4JR51FBMfy7LXOY%2BqspfSZzLQKWkg%2BBQEtVaaXh1hcDfcc8YKau5AHN69Z8pKjm%2Bl%2BWi%2Fx2q5dz2sYoJ9%2FZLn1HymgjefyyoQspvKaK3vOxIWd%2FvJa5EsfknAoIMKDrTN3A1TuNK%2B5EZz8UprSikJt1N6xV0FY3aoOQjyKhxkaQ%2BZmNj27bjc6X1f%2BbuIBmV85%2BuN3ZhINcDV9hSfqdJqu06aOuUGq8icuL14h6leyugrBsPF2kbiLppy%2Fj27Srdag5xfx6J%2BJtaKwVc1IWuTy63fWMhc%2Bk%2Fzuks6wd594OEU;Version=1;Path=/;Expires=Tue, 06-Dec-2016 13:26:35 GMT;Max-Age=3600;HttpOnly;Comment=generic_user
    Expires: Thu, 01 Jan 1970 00:00:00 GMT
    X-Auth-Token: r%2BrlCMT9lZSHW%2BoOp2Lp2OXvR%2Bq%2FrOVGIBe39RxZIkZgz7lC8WrjXhI%2B40nN89W2aB0JZO4X7sT0%2BWxo6Aglv%2FqyvwjUYB8Q2SCLqqx%2BmpaoOXBXLbwQQqdG7EBGc8MPl%2BkWR4g69pZEFurtMUEOSYu9dEXpKN2yVyFGo9EcX1kE9YfKvNTBrSyS1S2Vh0l1SFtwKVBFUJ5XQSrX%2FoSn0syaIAw8dPPetDHns9s0AfYyqStbcH5uOlr3QVTsN%2Fx4jS0%2F9%2FlK9tIvBFQCdhqcNsmgZXTqM36Zxw2Y4sV6Ri6u22c2Hk6Y4jPWVcs%2F3KfLzQmD4b1zK2U2yxYQ6gqEeDBdDzyke9ozqRJuelT%2BK7G28zbANXRr91q%2FgGlG3AkUYo7Ak%2FBhq88O8z799iDfmHxca1Jfb8jKy1qGJn77jwIKxYpZzEpZNm1T%2BkWpMe0lRvqZ2eHg7VYFKWiHgPQleNwdosxbmOrbZqtEejNVutrgVN%2Fm1JytPnTldZzueyexIw2MrFDZvZSrRuzt0CMWoCA9nlriTaUksILZjFuJeeGjGHhzQXI1X3xPhet6qk8pkrj4BNiHKZyiAcOw6mtyeLiKuyVoWWMbBN3mJsU7LWpj3Kg18%2Bu%2BcF%2F%2BbPH%2BDiz%2BPrnhyYEeHOeavN8uOkvQU%2Fws12VSkY8zC9SlS3RIfZSh2RYoVFXScQgDXjPYxFCJjULEV5ARfqmqEyOXNm%2Fp2YnEG3H%2F4EQ8nJMTDJlD7UjK%2FVxRSgTzlFyNSVTkRuDV9mSXyVlpdxStMgCbCcVYOKDKA5MI%2Fhtk7kB%2BsBjXjXE2cPGt3%2B9A2%2FKOj%2BL8pkFR%2BO8vDxTFuP4f4Wy%2BZvb6G4iHnwBF1kSnnEHVCPDjsvJKvvDYg7eGGAWCcNMDi9JL
    Content-Type: application/json;charset=UTF-8
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    X-Frame-Options: SAMEORIGIN
    Transfer-Encoding: chunked
      
    {"authorities":["ROLE_USER","PRIVILEGE_DATA_VIEW"],"enabled":true,"id":"1","name":"test_user","password":"[PROTECTED]","username":"test_user"}
  
> lib-security分别在 `Cookie` 和 `X-Auth-Token` header中，返回了token信息,这里由于没有配置加密，所以token仅仅做了URLEncode。
在Response Body中返回用户基本信息。

- 资源访问
  
	支持客户端在请求资源时，以如下两种方式携带token信息(token信息即用户登录成功后，在cookie和X-Auth-Token中返回的数据)。  

> Cookie方式
    
	curl -i -X GET -L --COOKIE "generic_user=%7B%22accountNonExpired%22%3Atrue%2C%22accountNonLocked%22%3Atrue%2C%22authorities%22%3A%5B%22ROLE_USER%22%2C%22PRIVILEGE_DATA_VIEW%22%5D%2C%22credentialsNonExpired%22%3Atrue%2C%22enabled%22%3Atrue%2C%22password%22%3Anull%2C%22username%22%3A%22UT_USER%3E1%3Etest_user%22%2C%22properties%22%3A%7B%22email%22%3A%22user%40somedomain.com%22%7D%2C%22timestamp%22%3A%222016-12-12T15%3A01%3A36.918%2B08%3A00%22%2C%22uuid%22%3A%22b8dd33cca0a6422aace507aaf6d06206%22%2C%22id%22%3A%221%22%7D;Version=1;Path=/;Expires=Mon, 12-Dec-2016 08:01:37 GMT;Max-Age=3600;HttpOnly;Comment=generic_user" http://127.0.0.1:8080:8080/users/current
	
	Response
	
	HTTP/1.1 200 OK
    Date: Mon, 12 Dec 2016 07:13:05 GMT
    X-Application-Context: application-quick:8080
    Content-Type: application/json;charset=UTF-8
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    Cache-Control: no-cache, no-store, max-age=0, must-revalidate
    Pragma: no-cache
    Expires: 0
    X-Frame-Options: SAMEORIGIN
    Transfer-Encoding: chunked
      
    {"authorities":["ROLE_USER","PRIVILEGE_DATA_VIEW"],"enabled":true,"id":"1","name":"test_user","password":"[PROTECTED]","username":"test_user"}

> X-Auth-Token方式
    
	curl -i -X GET -L --HEADER "X-Auth-Token: %7B%22accountNonExpired%22%3Atrue%2C%22accountNonLocked%22%3Atrue%2C%22authorities%22%3A%5B%22ROLE_USER%22%2C%22PRIVILEGE_DATA_VIEW%22%5D%2C%22credentialsNonExpired%22%3Atrue%2C%22enabled%22%3Atrue%2C%22password%22%3Anull%2C%22username%22%3A%22UT_USER%3E1%3Etest_user%22%2C%22properties%22%3A%7B%22email%22%3A%22user%40somedomain.com%22%7D%2C%22timestamp%22%3A%222016-12-12T15%3A01%3A36.918%2B08%3A00%22%2C%22uuid%22%3A%22b8dd33cca0a6422aace507aaf6d06206%22%2C%22id%22%3A%221%22%7D" http://127.0.0.1:8080:8080/users/current
    
    Response
    
	HTTP/1.1 200 OK
    Date: Mon, 12 Dec 2016 07:15:31 GMT
    X-Application-Context: application-quick:8080
    Content-Type: application/json;charset=UTF-8
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    Cache-Control: no-cache, no-store, max-age=0, must-revalidate
    Pragma: no-cache
    Expires: 0
    X-Frame-Options: SAMEORIGIN
    Transfer-Encoding: chunked
      
    {"authorities":["ROLE_USER","PRIVILEGE_DATA_VIEW"],"enabled":true,"id":"1","name":"test_user","password":"[PROTECTED]","username":"test_user"}

- 测试登出


	curl -i -X GET -L -b COOKIE http://127.0.0.1:8080:8080/auth/logout
	
	Response
	
	HTTP/1.1 200 OK
    Date: Mon, 12 Dec 2016 07:16:41 GMT
    Set-Cookie: generic_user=;Version=1;Path=/;Expires=Thu, 01-Jan-1970 00:00:00 GMT;Max-Age=0;HttpOnly;Comment=generic_user
    Expires: Thu, 01 Jan 1970 00:00:00 GMT
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    X-Frame-Options: SAMEORIGIN
    Content-Length: 0

> 登出请求成功后，用户的cookie和token信息都被清空了，

# Template应用接入lib-security

## 简介
> 模版应用包括Velocity、Thymeleaf等模版构建的web应用，前后端的资源集成在一起部署。
  
#### 接入示例
##### application.yml配置如下
    
	app:
	  type: TEMPLATE
	  security:
	    basePath: '/auth'
	    cookieKey: 'AES256_CBC16:YDD7uVFNpvkId8HWI6xTfOeRW3O6Wk3FDuGJdnGDhiD='
	    defaultTestUser: 'test_user'
	    enabled: true
	    jwtKey: 'HS512:Ve+/vU5u77+977+977+977+977+9Acu/77+977+977+9OXrvv71XH++/vRLvv73vv73vv73vv71577+9fQLvv73vv71eB++/vW7vv71g77+977+977+9L++/vWDvv73vv73vv71577+9VO+/ve+/vR3vv73vv73Coemfv++/ve+/vQ=='
	    loginKey: 'RSA1024_PAIR_PKCS1_X509:MIICWwIBAAKBgQCRXunHa+5hw+L39UZoIFhPwPR9gBvdlEvlXAH4biP+GNb8OH77OjMsfjfs3dXs3QqwXMajJUKZFpX1v+w/ilZ9muvty4/wfQlx5qy305Ui6mRqpIQKKxkwgAS+LTVCh+AeFWfB9G/OVA/khp73VQ3/IPoqgcPG+e/RD/kdFwTozwIDAQABAoGAALbYqzQqjaxqtxErcWOHS40FJoC0olgSL2ROViwkXSE+HSsh5JYankNYfv9wB6PmY4txJmgOdbYYsoZo4L8LQbzV02cEzAibAltvS8JUZ0XWNbnhRnSvY+GJ24hf1BHIJGjBnkQDK/XrDw8Xzt2bSDlWyWH4iEC7PgpghQpHRZECQQDB1GK0U3iDofSJkdLpypxWE6T6MBl7RJCOROj56cXIaVcamOKD1D+x+aDrP7wH2Crhn5X83cTDGekDEIzs0tHjAkEAv/+A4QP61ZgEKn+1gk7RHw/tWHBLWhb1EcIpShBNWx8sB4G8wI7brf858iLXl9NhROkcqYmbchG3D6SnYZmRJQJAR8kxBTgk2huRRaIMSyoO3JJJ95740P6Dyy0aW/SIm8Dn0aHtwoVJUdDyGC5ypTUaLJW+Jvi7dsaR1eC7ULqDoQJAHoSNRrbsOuEz4FF2V2URxl8wubr3rzUw9Qaoq3YV5aL5y6OqjeznLCwCWOOC40YdEuf+v0/5HlOEhn8Ef/X55QJAKktna3oDVsfsTH6REVLz8kjvhILJ5yk493/yjTZxpcpcVv8LGjuCKtIn3NdCRoeIC1K+oLzbBB6U+J8Uu5aeSA==:MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRXunHa+5hw+L39UZoIFhPwPR9gBvdlEvlXAH4biP+GNb8OH77OjMsfjfs3dXs3QqwXMajJUKZFpX1v+w/ilZ9muvty4/wfQlx5qy305Ui6mRqpIQKKxkwgAS+LTVCh+AeFWfB9G/OVA/khp73VQ3/IPoqgcPG+e/RD/kdFwTozwIDAQAB'
	    loginProcessingUrl: '/login'
	    loginPublicKeyUrl: '/login/rsaPublicKey'
	    logoutUrl: '/logout'
	    permited: '/fonts/*,/img/*,/images/*,/js/*,/login*,/css/*'
	    loginPage : '/login.do'
	    authSucessHandler : '/cluster/list.do'

##### 用户模型
> 继承`cn.home1.oss.lib.security.api.AbstractUser`类并实现父类抽象方法，按需覆写父类方法。关于额外的用户信息，可以通过扩展`public Map<String, Object> 
getProperties()`来实现

##### 角色模型  
> 继承 `cn.home1.oss.lib.security.api.AbstractRole` 类，来存储用户角色的信息，

##### 权限模型  
> 继承`cn.home1.oss.lib.security.api.StaticPrivilege`类，来做静态资源权限的定义,

##### Service层实现  
1. 继承`cn.home1.oss.lib.security.api.BaseUserDetailsAuthenticationProvider` 抽象类,
该类已经实现了`UserDetailsService`接口并hook了`ContextRefreshedEvent`事件.
2. lib-security不假定用户的存储逻辑，用户只需重写 findByName、save、delete等方法即可.  
3. 可以重写该类的 testUsers 方法，生成测试用户方便测试。 
4. lib-security配置中的defaultTestUser属性需要配合该方法使用，测试用户必须在用户提供的测试用户列表中进行选择。
 
##### Controller层实现
> 需要实现进入登陆页的入口和登陆成功后跳转的页面，这里成功后跳转到的页面没有列出
    
	@Controller
	@RequestMapping("/auth")
	public class AuthAction extends AbstractAction {
	    /**
	     * 登录页跳转
	     *
	     * @param map
	     * @param request
	     * @return
	     */
	    @RequestMapping(value = "/login", method = RequestMethod.GET)
	    public String login(ModelMap map, HttpServletRequest request) {
	        map.put(getFlag(), "active");
	        map.put(TITLE, "login");
	        return "login";
	    }
	}
