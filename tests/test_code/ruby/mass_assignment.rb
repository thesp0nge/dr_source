# Ruby on Rails Mass Assignment
class UsersController < ApplicationController
  def create
    # VULNERABLE: Direct params passed to create
    @user = User.create(params[:user]) # Line 5
  end

  def update
    @user = User.find(params[:id])
    # VULNERABLE: Direct params passed to update
    @user.update(params[:user]) # Line 11
  end
end
