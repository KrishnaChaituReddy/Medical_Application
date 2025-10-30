import { Component, OnInit } from '@angular/core';
import { AuthService } from '../services/auth.service';
import { Router } from '@angular/router';
 
@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit {
  IsLoggin = false;
  roleName: string | null = null;
 
  constructor(private authService: AuthService, private router: Router) {}
 
  ngOnInit(): void {
    // this.authService.loggedIn$.subscribe(status => this.IsLoggin = status);
    // this.authService.userRole$.subscribe(role => this.roleName = role);
    this.IsLoggin=this.authService.getLoginStatus;
    this.roleName=this.authService.getRole;
    if (this.IsLoggin=false) {
      this.router.navigateByUrl('/login');
    }
  }
 
  logout() {
    this.authService.logout();
    this.router.navigateByUrl('/login');
   // this.roleName="";
  }
}
 
 