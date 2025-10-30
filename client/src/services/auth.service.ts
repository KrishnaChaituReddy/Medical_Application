import { Injectable } from '@angular/core';
 
@Injectable({
  providedIn: 'root'
})
export class AuthService {
 
  private token: string | null = null;
  private isLoggedIn: boolean = false;
 
  constructor() {}
 
  // Method to save token received from login
  saveToken(token: string) {
   this.token=token;
   localStorage.setItem('authToken',token);
   this.isLoggedIn=true;
  }
   SetRole(role:any)
  {
     localStorage.setItem('role',role);
  }
  get getRole ():string|null
  {
    return localStorage.getItem('role');
  }
  // Method to retrieve login status
  get getLoginStatus(): boolean {
  const token=localStorage.getItem('authToken');
  return token!==null;
      //please complete this
   
  }
  getToken(): string | null {
 
  return localStorage.getItem('authToken');
  }
  logout(){
localStorage.removeItem('authToken');
localStorage.removeItem('role');
this.token = null;
this.isLoggedIn = false;
   }
}