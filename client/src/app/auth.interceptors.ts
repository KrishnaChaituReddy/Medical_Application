import { Injectable } from "@angular/core";
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
} from "@angular/common/http";
import { Observable } from "rxjs";
import { HttpService } from "../services/http.service";
import { AuthService } from "../services/auth.service";
 
 
@Injectable({
  providedIn: 'root'
})
export class AuthInterceptor implements HttpInterceptor {
 
  constructor(private httpService: HttpService, private authService: AuthService) {}
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = this.authService.getToken();
    if (req.url.includes("login") || req.url.includes("register")) {
        req = req.clone({
            setHeaders: {
              "Content-Type": "application/json; charset=utf-8",
              Accept: "application/json",
            },
          });
      return next.handle(req);
    }
 
    if (token) {
      req = req.clone({
        setHeaders: {
          "Content-Type": "application/json; charset=utf-8",
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
        },
      });
    }
 
    return next.handle(req);
  }
}
 
 