package cn.home1.oss.lib.security.swagger;

import static com.google.common.collect.Sets.newHashSet;
import static springfox.documentation.schema.ResolvedTypes.modelRefFactory;

import cn.home1.oss.lib.errorhandle.api.ResolvedError;
import cn.home1.oss.lib.swagger.ManualRequestHandler;
import cn.home1.oss.lib.swagger.model.ApiOperationInfo;

import com.fasterxml.classmate.TypeResolver;

import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;

import springfox.documentation.RequestHandler;
import springfox.documentation.builders.OperationBuilder;
import springfox.documentation.builders.ResponseMessageBuilder;
import springfox.documentation.schema.ModelReference;
import springfox.documentation.schema.TypeNameExtractor;
import springfox.documentation.service.ResponseMessage;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.schema.contexts.ModelContext;
import springfox.documentation.spi.service.OperationBuilderPlugin;
import springfox.documentation.spi.service.contexts.OperationContext;
import springfox.documentation.spi.service.contexts.RequestMappingContext;

import java.lang.reflect.Field;
import java.util.Set;

/**
 * Created on 16/11/1. Desc : Run after scanning operationBuilder plugin
 */
@Slf4j
abstract public class AbstractAfterOperationBuilderBuildPlugin implements OperationBuilderPlugin {

  private static final String MANUAL_REQUEST_HANDLER = ManualRequestHandler.class.getSimpleName();

  @Autowired
  private TypeNameExtractor nameExtractor;

  @Autowired
  protected TypeResolver typeResolver;

  @Override
  public void apply(final OperationContext context) {
    try {
      // 处理自定义的请求处理器
      if (MANUAL_REQUEST_HANDLER.equals(context.getName())) {

        // get requestContext
        Field privateStringField = OperationContext.class.getDeclaredField("requestContext");
        privateStringField.setAccessible(true);
        final RequestMappingContext requestMappingContext = //
          (RequestMappingContext) privateStringField.get(context);

        // get handler
        privateStringField = RequestMappingContext.class.getDeclaredField("handler");
        privateStringField.setAccessible(true);
        final RequestHandler requestHandler = (RequestHandler) privateStringField.get(requestMappingContext);

        if (requestHandler instanceof ManualRequestHandler) {
          this.processRequestHandler(context, (ManualRequestHandler) requestHandler);
        }
      }

      // 处理响应的错误码对应的ResolveError
      processResponseModel(context);
    } catch (final ReflectiveOperationException ex) {
      log.error("swagger plugin error.", ex);
    }
  }

  private void processRequestHandler(final OperationContext context, final ManualRequestHandler manualRequestHandler) {
    final ApiOperationInfo apiOperationInfo = manualRequestHandler.getApiOperationInfo();

    if (apiOperationInfo != null) {
      // 接口描述
      context.operationBuilder().notes(apiOperationInfo.getNotes());
      // 请求参数处理
      if (apiOperationInfo.getApiRequest().getParameters() != null) {
        context.operationBuilder().parameters(apiOperationInfo.getApiRequest().getParameters());
      }
    }
  }

  /**
   * 为错误码的响应增加Model的映射 @cn.home1.oss.lib.errorhandle.api.ResolvedError
   */
  private void processResponseModel(final OperationContext context) {
    try {
      final OperationBuilder operationBuilder = context.operationBuilder();
      final Field privateStringField = OperationBuilder.class.getDeclaredField("responseMessages");
      privateStringField.setAccessible(true);
      final Set<ResponseMessage> responseMessages = (Set<ResponseMessage>) privateStringField.get(operationBuilder);

      final ModelContext modelContext = this.modelContext(context);
      final ModelReference responseModel = modelRefFactory(modelContext, this.nameExtractor) //
        .apply(context.alternateFor(this.typeResolver.resolve(ResolvedError.class)));

      final Set<ResponseMessage> responseMessagesProcessed = newHashSet();
      responseMessages.stream().forEach((responseMessage -> {
        if (!isSuccessful(responseMessage.getCode())) {
          responseMessagesProcessed.add(new ResponseMessageBuilder()
            .code(responseMessage.getCode())
            .message(responseMessage.getMessage())
            .responseModel(responseModel)
            .build());
        }
      }));
      if (!responseMessagesProcessed.isEmpty()) {
        context.operationBuilder().responseMessages(responseMessagesProcessed);
      }
    } catch (final NoSuchFieldException | IllegalAccessException ex) {
      log.info("error processResponseModel.", ex);
    }
  }

  abstract protected ModelContext modelContext(OperationContext context);

  /**
   * 判断是否是成功的响应.
   */
  private static boolean isSuccessful(final int code) {
    try {
      return HttpStatus.Series.SUCCESSFUL.equals(HttpStatus.Series.valueOf(code));
    } catch (final Exception ignored) {
      log.info("error check httpStatus {}.", code, ignored);
      return false;
    }
  }

  @Override
  public boolean supports(final DocumentationType delimiter) {
    return DocumentationType.SWAGGER_2.equals(delimiter);
  }
}
