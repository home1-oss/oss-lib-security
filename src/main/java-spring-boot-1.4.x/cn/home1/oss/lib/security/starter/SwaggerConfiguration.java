package cn.home1.oss.lib.security.starter;

import static cn.home1.oss.boot.autoconfigure.AppSecurity.ENABLED;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import cn.home1.oss.boot.autoconfigure.ConditionalOnAppSecurity;
import cn.home1.oss.boot.autoconfigure.ConditionalOnNotEnvProduction;
import cn.home1.oss.lib.security.swagger.AfterOperationBuilderBuildPlugin;
import cn.home1.oss.lib.security.swagger.AuthenticationTokenHeaderBuilderPlugin;
import cn.home1.oss.lib.security.swagger.BasicAuthHeaderBuilderPlugin;
import cn.home1.oss.lib.security.swagger.SecurityApiDocumentationPlugin;

@ConditionalOnClass(name = {"springfox.documentation.RequestHandler"})
@ConditionalOnNotEnvProduction
@Configuration
public class SwaggerConfiguration {

  @Bean
  @ConditionalOnAppSecurity(ENABLED)
  public AuthenticationTokenHeaderBuilderPlugin authenticationTokenHeaderBuilderPlugin() {
    return new AuthenticationTokenHeaderBuilderPlugin();
  }

  @Bean
  @ConditionalOnAppSecurity(ENABLED)
  public BasicAuthHeaderBuilderPlugin basicAuthHeaderBuilderPlugin() {
    return new BasicAuthHeaderBuilderPlugin();
  }

  @Bean
  @ConditionalOnAppSecurity(ENABLED)
  public SecurityApiDocumentationPlugin securityApiDocumentationPlugin() {
    return new SecurityApiDocumentationPlugin();
  }

  @Bean
  @ConditionalOnAppSecurity(ENABLED)
  public AfterOperationBuilderBuildPlugin afterOperationBuilderBuildPlugin() {
    return new AfterOperationBuilderBuildPlugin();
  }
}
