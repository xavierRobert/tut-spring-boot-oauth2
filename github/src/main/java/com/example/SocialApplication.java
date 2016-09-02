/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.security.Principal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

@SpringBootApplication
@RestController
@EnableOAuth2Client
@EnableAuthorizationServer
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Order(6)
public class SocialApplication extends WebSecurityConfigurerAdapter {

	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	@RequestMapping({ "/user", "/me" })
	public Map<String, String> user(Principal principal) {
		Map<String, String> map = new LinkedHashMap<>();
		map.put("name", principal.getName());
		return map;
	}

    @Bean
    public OAuth2RestTemplate oauth2RestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
        return new OAuth2RestTemplate(resource, context);
    }

    @Bean
    public AuthoritiesExtractor authoritiesExtractorFacebook(OAuth2RestOperations template) {
        return map -> {
			return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_OAUTH, ROLE_LOGIN, ROLE_FACEBOOK");
        };
    }
    @Bean
    public AuthoritiesExtractor authoritiesExtractorGithub(OAuth2RestOperations template) {
        return map -> {
			return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_OAUTH, ROLE_LOGIN, ROLE_GITHUB");
        };
    }
    @Bean
    public AuthoritiesExtractor authoritiesExtractorGoogle(OAuth2RestOperations template) {
        return map -> {
			return AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_OAUTH, ROLE_LOGIN, ROLE_GOOGLE");
        };
    }

    //Add users that will be used for the HTTP basic login
    @Autowired
    public void configureGlobalSecurity(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("admin").password("4321").roles("ADMIN", "LOGIN"); //adds authorities ROLE_ADMIN
        auth.inMemoryAuthentication().withUser("user").password("4321").roles("USER", "LOGIN"); //adds authorities ROLE_USER
    }

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off

        //BOTH 2
        http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
                .authenticated()

                //HTTP Basic
//                .and().httpBasic().realmName("MY_TEST_REALM").authenticationEntryPoint(getBasicAuthEntryPoint())
//                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                //OAUTH2
                .and().exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/"))
                //.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().logout().logoutSuccessUrl("/").permitAll()
                .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and().addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

        //BOTH 1
//        http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
//                .authenticated()
//                .and().httpBasic().realmName("MY_TEST_REALM").authenticationEntryPoint(getBasicAuthEntryPoint())
//                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and().exceptionHandling()
//                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and().logout()
//                .logoutSuccessUrl("/").permitAll().and().csrf()
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
//                .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

        //OAUTH2
//		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest()
//				.authenticated().and().exceptionHandling()
//				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and().logout()
//				.logoutSuccessUrl("/").permitAll().and().csrf()
//				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
//				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);

        //HTTPBASIC
//		http.csrf().disable()
//				.authorizeRequests()
//				.antMatchers("/**").hasRole("LOGIN")
//				.and().httpBasic().realmName("MY_TEST_REALM").authenticationEntryPoint(getBasicAuthEntryPoint())
//				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);//We don't need session.

		// @formatter:on
	}

	@Bean
	public CustomBasicAuthenticationEntryPoint getBasicAuthEntryPoint(){
		return new CustomBasicAuthenticationEntryPoint();
	}

	@Configuration
	@EnableResourceServer
	protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.antMatcher("/me").authorizeRequests().anyRequest().authenticated();
			// @formatter:on
		}
	}

	public static void main(String[] args) {
		SpringApplication.run(SocialApplication.class, args);
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	@Bean
	@ConfigurationProperties("github")
	public ClientResources github() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
		return new ClientResources();
	}

	@Bean
	@ConfigurationProperties("google")
	public ClientResources google() {
		return new ClientResources();
	}

	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<>();
		filters.add(ssoFilter(facebook(), "/login/facebook"));
		filters.add(ssoFilter(github(), "/login/github"));
		filters.add(ssoFilter(google(), "/login/google"));
		filter.setFilters(filters);
		return filter;
	}

    /**
     * Here we define which authorities are added depending on the login provider
     * @param client
     * @param path
     * @return
     */
	private Filter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter oAuth2ClientAuthenticationFilter = new OAuth2ClientAuthenticationProcessingFilter(
				path);
		OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		oAuth2ClientAuthenticationFilter.setRestTemplate(oAuth2RestTemplate);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(client.getResource().getUserInfoUri(),
				client.getClient().getClientId());
		tokenServices.setRestTemplate(oAuth2RestTemplate);
		switch (path){
			case "/login/facebook":
				tokenServices.setAuthoritiesExtractor(authoritiesExtractorFacebook(oAuth2RestTemplate));
				break;
			case"/login/github":
				tokenServices.setAuthoritiesExtractor(authoritiesExtractorGithub(oAuth2RestTemplate));
				break;
			case"/login/google":
				tokenServices.setAuthoritiesExtractor(authoritiesExtractorGoogle(oAuth2RestTemplate));
				break;
		}

		oAuth2ClientAuthenticationFilter.setTokenServices(tokenServices);
		return oAuth2ClientAuthenticationFilter;
	}

}

class ClientResources {

	@NestedConfigurationProperty
	private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();

	@NestedConfigurationProperty
	private ResourceServerProperties resource = new ResourceServerProperties();

	public AuthorizationCodeResourceDetails getClient() {
		return client;
	}

	public ResourceServerProperties getResource() {
		return resource;
	}
}
