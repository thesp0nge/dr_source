require 'marshal'

class RceController
  def index
    data = params[:data]
    # VULNERABLE: INSECURE_DESERIALIZATION
    Marshal.load(data)
  end
end
