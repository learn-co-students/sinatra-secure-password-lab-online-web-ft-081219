require "./config/environment"
require "./app/models/user"
class ApplicationController < Sinatra::Base

  configure do
    set :views, "app/views"
    enable :sessions
    set :session_secret, "password_security"
  end

  get "/" do
    erb :index
  end

  get "/signup" do
    erb :signup
  end

  post "/signup" do
    user = User.create(:username => params[:username], :password => params[:password], :balance => 0)
    if user.save && !user[:username].empty?
      user.save
      redirect "/login"
    else
      redirect "/failure"
    end
  end

  get '/account' do
    if logged_in?
      @user = current_user
      erb :account
    else
      redirect "/failure"
    end
  end
  
  post '/account' do
    balance = current_user[:balance]
    if params[:deposit].to_i > 0
      current_user.update(:balance => (balance + params[:deposit].to_i))
    end
    if params[:withdraw].to_i > 0 && params[:withdraw].to_i < current_user[:balance]
      current_user.update(:balance => (balance - params[:withdraw].to_i))
    end
    redirect '/account'
  end

  get "/login" do
    erb :login
  end

  post "/login" do
    user = User.find_by(:username => params[:username])
    if user && user.authenticate(params[:password])
      session[:user_id] = user.id
      redirect "/account"
    else
      redirect "/failure"
    end
  end

  get "/failure" do
    erb :failure
  end

  get "/logout" do
    session.clear
    redirect "/"
  end

  helpers do
    def logged_in?
      !!session[:user_id]
    end

    def current_user
      User.find(session[:user_id])
    end
  end

end
