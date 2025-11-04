import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { HttpService } from '../../services/http.service';
import { AuthService } from '../../services/auth.service';
import { catchError, of, tap } from 'rxjs';
 
 
 
@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
 
  itemForm!:FormGroup;
  errorMessage: string="";
  successMessage:string="";
  constructor(private fb:FormBuilder,private authService:AuthService,private router:Router,private httpService:HttpService)
  {
 
  }
  ngOnInit(): void {
 
    this.itemForm=this.fb.group(
      {
        username:["",Validators.required],
        password:["",Validators.required]
      }
    );
  }
  onSubmit(): void {
    if (this.itemForm.valid) {
      const formData = this.itemForm.value;
      this.httpService.login(formData).pipe(
        tap((response) => {
          console.log(response);
  
          // Save token using AuthService
          this.authService.saveToken(response.token);
          this.authService.SetRole(response.role);
  
          localStorage.setItem("role", response.role);
          localStorage.setItem("username", response.username);
  
          console.log(localStorage.getItem("role"));
          console.log("Token:", this.authService.getToken());
  
          // Navigate to dashboard
          this.router.navigate(['/dashboard']);
        }),
        catchError((error) => {
          this.errorMessage = 'Invalid username or password';
          console.error("Login error:", error);
  
         
          setTimeout(() => {
            this.errorMessage = '';
            this.itemForm.reset();
          }, 1500);
  
          return of(null);
        })
      ).subscribe();
    } else {
      this.errorMessage = 'Please fill out the form correctly.';
  
    
      setTimeout(() => {
        this.errorMessage = '';
      }, 1500);
    }
  }
}
