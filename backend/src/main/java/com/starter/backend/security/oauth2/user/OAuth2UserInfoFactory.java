package com.starter.backend.security.oauth2.user;

import java.util.Map;

import com.starter.backend.enums.Provider;
import com.starter.backend.exception.OAuth2AuthenticationProcessingException;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(Provider.GOOGLE.toString())) {
            return new GoogleOAuth2UserInfo(attributes);    
        } else if (registrationId.equalsIgnoreCase(Provider.FACEBOOK.toString())) {
            return new FacebookOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(Provider.GITHUB.toString())) {
            return new GithubOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }
}
