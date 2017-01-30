package com.dpod.security;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.util.StringUtils;

public class CustomLdapAuthenticationProvider extends LdapAuthenticationProvider {

	public CustomLdapAuthenticationProvider(LdapAuthenticator authenticator) {
		super(authenticator);
	}

	public CustomLdapAuthenticationProvider(LdapAuthenticator authenticator,
			LdapAuthoritiesPopulator authoritiesPopulator) {
		super(authenticator, authoritiesPopulator);
	}

	@Override
	protected DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken authentication) {
		UsernamePasswordAuthenticationToken copiedToken = new UsernamePasswordAuthenticationToken(
				toTwoCapitalizedWords(authentication.getPrincipal()), authentication.getCredentials(),
				authentication.getAuthorities());
		copiedToken.setAuthenticated(authentication.isAuthenticated());
		copiedToken.setDetails(authentication.getDetails());
		return super.doAuthentication(copiedToken);
	}

	private Object toTwoCapitalizedWords(Object principal) {
		if (principal == null || !(principal instanceof String)) {
			return principal;
		}
		String username = (String) principal;
		String[] splitted = username.split("\\.");
		if (splitted.length != 2) {
			return principal;
		}
		return StringUtils.capitalize(splitted[0]) + " " + StringUtils.capitalize(splitted[1]);
	}

}
