import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { HttpService } from '../../services/http.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-forgotpassword',
  templateUrl: './forgotpassword.component.html',
  styleUrls: ['./forgotpassword.component.scss']
})
export class ForgotpasswordComponent implements OnInit {
    forgotForm!: FormGroup;
    resetForm!: FormGroup;
    otpSent = false;
  successMessage: any;
  errorMessage: any;
  loading= false;
  otpError=false;
  MailError:any;
  
    constructor(private fb: FormBuilder, private httpService: HttpService, private router: Router) {}
  
    ngOnInit(): void {
      this.forgotForm = this.fb.group({
        email: ['', [Validators.required, Validators.email]]
      });
  
      this.resetForm = this.fb.group({
        otp: ['', Validators.required],
        newPassword : ['',[Validators.required,Validators.pattern(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@$%&*?])[A-Za-z\d!@$%&*?]{8,}$/)]],
      });
    }
    get f(){
      return this.resetForm.controls;
     }
    sendOtp(): void {
      const email = this.forgotForm.value.email;
    
      this.httpService.sendOtp(email).subscribe({
        next: () => {
          this.otpSent = true;
  
          this.loading = false;
          this.MailError=null;
        },
        error: (err) => {
          this.otpSent = false;
          this.successMessage = null;
          this.loading = false;
      
          this.MailError=err.MailError||'Email not registered';
          
  setTimeout(() => {
    // this.errorMessage = null;
    this.MailError=null;
    this.forgotForm.reset();
  }, 1500);

        }
      });
    }
    
    otpValidated = false;
   

    validateOtp(): void {
      const email = this.forgotForm.value.email;
      const otp = this.resetForm.value.otp;
    
      this.httpService.verifyOtp(email, otp).subscribe({
        next: () => {
          this.otpValidated = true;
          this.errorMessage = null;
        },
        error: (err) => {
          this.otpValidated = false;
          this.errorMessage = err.error.message || 'Invalid OTP';
          setTimeout(() => this.errorMessage = null, 1500);
        }
      });
    }
         
   
resetPassword(): void {
  const email = this.forgotForm.value.email;
  const { otp, newPassword } = this.resetForm.value;

  this.httpService.resetPassword({ email, otp, newPassword }).subscribe({
    next: (res) => {
      this.successMessage = res.message;
  
      // Redirect after short delay
      setTimeout(() => {
        this.router.navigate(['/login']);
      }, 2000);
    },
   
// error: (err) => {
//   if (err.error.message === 'Invalid OTP') {
//     this.errorMessage = 'The OTP you entered is incorrect. Please try again.';
//   } else {
//     this.errorMessage = err.error.message || 'Failed to reset password';
//   }
// }

  });
}
}