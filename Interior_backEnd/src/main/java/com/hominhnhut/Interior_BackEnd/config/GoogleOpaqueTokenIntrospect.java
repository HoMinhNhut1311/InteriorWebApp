//package com.hominhnhut.WMN_BackEnd.config;
//
//
//import com.hominhnhut.WMN_BackEnd.domain.request.UserGoogleInfo;
//import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
//import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
//import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
//import org.springframework.web.reactive.function.client.WebClient;
//
//import java.util.HashMap;
//import java.util.Map;
//
//public class GoogleOpaqueTokenIntrospect implements OpaqueTokenIntrospector {
//
//    private final WebClient webClient;
//
//    public GoogleOpaqueTokenIntrospect(WebClient webClient) {
//        this.webClient = webClient;
//    }
//
//    @Override
//    public OAuth2AuthenticatedPrincipal introspect(String token) {
//        UserGoogleInfo userInfor = webClient.get().
//                uri(uriBuilder -> uriBuilder.path("/oauth2/v3/userinfo").
//                        queryParam("access_token",token).build())
//                .retrieve()
//                .bodyToMono(UserGoogleInfo.class).block();
//        Map<String, Object> attributes = new HashMap<>();
//        assert userInfor != null;
//        attributes.put("sub",userInfor.sub());
//        attributes.put("name", userInfor.name());
//
//        return new OAuth2IntrospectionAuthenticatedPrincipal(userInfor.name(),attributes,null);
//    }
//}
