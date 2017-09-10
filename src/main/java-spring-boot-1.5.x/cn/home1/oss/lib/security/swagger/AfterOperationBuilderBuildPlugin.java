package cn.home1.oss.lib.security.swagger;

import static springfox.documentation.spi.schema.contexts.ModelContext.returnValue;

import org.springframework.core.annotation.Order;

import springfox.documentation.spi.schema.contexts.ModelContext;
import springfox.documentation.spi.service.contexts.OperationContext;
import springfox.documentation.swagger.common.SwaggerPluginSupport;

/**
 * Created on 16/11/1. Desc : Run after scanning operationBuilder plugin
 */
@Order(SwaggerPluginSupport.SWAGGER_PLUGIN_ORDER + 10)
public class AfterOperationBuilderBuildPlugin extends AbstractAfterOperationBuilderBuildPlugin {

  @Override
  protected ModelContext modelContext(final OperationContext context) {
    final String groupName = "security";

    return returnValue( //
      groupName,
      this.typeResolver.resolve(context.getReturnType()),
      context.getDocumentationType(),
      context.getAlternateTypeProvider(),
      context.getGenericsNamingStrategy(),
      context.getIgnorableParameterTypes());
  }
}
