class MessagesController < ApplicationController
  # before_action :require_user

  def create
    message = current_user.messages.build(message_params)
    if message.save
      flash[:message] = "messages created"
      redirect_to chatrooms_path
    else
      flash[:message] = "message not created"
    end
  end



  def message_params
    params.require(:message).permit(:body)
  end
end
