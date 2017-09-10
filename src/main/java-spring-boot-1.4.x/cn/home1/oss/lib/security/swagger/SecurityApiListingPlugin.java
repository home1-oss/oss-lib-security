package cn.home1.oss.lib.security.swagger;

import org.springframework.core.annotation.Order;

import springfox.documentation.spi.service.contexts.ApiListingContext;
import springfox.documentation.swagger.common.SwaggerPluginSupport;

/**
 * Created by zhanghaolun on 16/10/31.
 */
@Deprecated
@Order(value = SwaggerPluginSupport.SWAGGER_PLUGIN_ORDER)
public class SecurityApiListingPlugin extends AbstractSecurityApiListingPlugin { //

  protected Class<?> controllerClass(final ApiListingContext apiListingContext) {
    return apiListingContext.getResourceGroup().getControllerClass();
  }
}
