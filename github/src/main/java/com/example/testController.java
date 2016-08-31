package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * Created by xavierrobert on 30/08/16.
 */
@RestController
public class testController {

    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    @RequestMapping(value = "/hola", method = RequestMethod.GET)
    @Secured("ROLE_ADMIN")
    public String hola(Principal principal){
        dumpSecurityContext();
        return "Hola " + principal.getName();
    }

    @RequestMapping(value = "/test", method = RequestMethod.GET)
    @Secured("ROLE_USER")
    public String hola(){
        dumpSecurityContext();
        return "Test " + "2";
    }

    @RequestMapping(value = "/oauth", method = RequestMethod.GET)
    @Secured("ROLE_OAUTH")
    public String oauth(){
        dumpSecurityContext();
        return "Oauth " + "2";
    }

    @RequestMapping(value = "/facebook", method = RequestMethod.GET)
    @Secured("ROLE_FACEBOOK")
    public String facebook(){
        dumpSecurityContext();
        return "facebook " + "2";
    }

    @RequestMapping(value = "/github", method = RequestMethod.GET)
    @Secured("ROLE_GITHUB")
    public String github(){
        dumpSecurityContext();
        return "github " + "2";
    }

    @RequestMapping(value = "/google", method = RequestMethod.GET)
    @Secured("ROLE_GOOGLE")
    public String google(){
        dumpSecurityContext();
        return "google " + "2";
    }

    private void dumpSecurityContext(){
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getAuthorities());
    }
}
