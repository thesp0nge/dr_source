# Ruby test case
class TestController
  def index
    id = params[:id]
    # VULNERABLE: LOG_INJECTION
    logger.info "Accessing record #{id}"

    klass_name = params[:class]
    # VULNERABLE: INSECURE_REFLECTION
    klass = klass_name.constantize
  end
end
