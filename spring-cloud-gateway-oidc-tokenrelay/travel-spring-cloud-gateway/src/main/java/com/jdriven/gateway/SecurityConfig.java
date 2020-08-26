package com.jdriven.gateway;

import org.springframework.http.HttpMethod;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
															ReactiveClientRegistrationRepository clientRegistrationRepository) {

		// Require authentication for all requests
		http.authorizeExchange()
			.pathMatchers(HttpMethod.GET, "/openfhir_api_war_exploded/Patient/*").hasAuthority("SCOPE_patient")
			.pathMatchers(HttpMethod.GET, "/").permitAll()
			.and()
			.authorizeExchange().anyExchange().authenticated();
		// Setting CORS
		http.cors()
			.configurationSource(this.corsConfigurationSource());
		// Disable CSRF in the gateway to prevent conflicts with proxied service CSRF
		http.csrf().disable();
		// Decode Token to check scope
		http.oauth2ResourceServer().jwt();
		return http.build();
	}

	private CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration corsConfiguration = new CorsConfiguration();
		corsConfiguration.addAllowedMethod(CorsConfiguration.ALL);
		corsConfiguration.addAllowedOrigin(CorsConfiguration.ALL);
		corsConfiguration.addAllowedHeader("Authorization");

		UrlBasedCorsConfigurationSource corsSource = new UrlBasedCorsConfigurationSource();
		corsSource.registerCorsConfiguration("/**", corsConfiguration);
		return corsSource;
	}

}
