package com.starter.backend.config;

import java.lang.annotation.Annotation;

import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.parameters.HeaderParameter;

@Configuration()
public class DocConfig {

	// private static final Logger logger =
	// LoggerFactory.getLogger(DocConfig.class);

	@Bean
	GroupedOpenApi Api() {
		return GroupedOpenApi.builder()
				.group("Apis")
				.addOperationCustomizer((operation, $) -> {

					Annotation[] annotations = $.getMethod().getAnnotations();
					String desiredAnnotationName = "org.springframework.web.bind.annotation";

					for (Annotation annotation : annotations) {
						String annotationTypeCanonicalName = annotation.annotationType().getCanonicalName();
						if (annotationTypeCanonicalName.startsWith(desiredAnnotationName)) {
							if (!annotation.annotationType().getSimpleName().equalsIgnoreCase("getmapping")) {
								operation.addParametersItem(
										new HeaderParameter()
												.name("X-XSRF-TOKEN")
												.required(true));
							}

						}
					}
					return operation;

				})
				.build();
	}

	@Bean
	public OpenAPI docAPI() {
		return new OpenAPI()
				.info(new Info()
						.title("WebStarter BACKEND")
						.description("This A backend template made for my future jobs and tasks")
						.contact(new Contact().email("alaa.leguefche@gmail.com"))
						.termsOfService("asdasdasd asdasd asd as dasd")
						.license(new License().name("").url(""))
						.version("0.0.1"));
	}

}
