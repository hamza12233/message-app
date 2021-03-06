Rails.application.routes.draw do
  devise_for :users
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html

  devise_scope :user do
    root to: 'devise/registrations#new'
  end

  resources :chatrooms
  post 'message', to: 'messages#create'
end
