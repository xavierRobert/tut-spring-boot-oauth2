package com.example;

import org.springframework.beans.factory.annotation.Autowired;
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
    public String hola(Principal principal){
        return "Hola " + principal.getName();
    }
}
