import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../environments/environment';
import { AuthService } from './auth.service';
 
@Injectable({
  providedIn: 'root'
})
export class HttpService {
  private serverName = `${environment.apiUrl}`;
 
  constructor(private http: HttpClient) {}
 
  register(credentials: any):Observable<any>{
    return this.http.post<any>(`${this.serverName}/api/user/register`,credentials)
  }
  login(credentials: any): Observable<any> {
    return this.http.post<any>(`${this.serverName}/api/user/login`, credentials);
  }
 
  createHospital(hospital:any) :Observable<any>
  {
   return this.http.post<any>(`${this.serverName}/api/hospital/create`,hospital);
  }
  getHospital() :Observable<any>
  {
    return this.http.get<any>(`${this.serverName}/api/hospitals`);
  }
 
  addEquipment(equipment: any, hospitalId: any): Observable<any> {
    return this.http.post<any>(`${this.serverName}/api/hospital/equipment?hospitalId=${equipment.hospitalId}`, equipment);
  }
 
  // Get all maintenance records
  getAllMaintenances(): Observable<any[]> {
    return this.http.get<any[]>(`${this.serverName}/api/technician/maintenance`);
  }
 
 
  // Update maintenance by ID
  updateMaintenance(maintenanceId: number, maintenance: any): Observable<any> {
    return this.http.put<any>(`${this.serverName}/api/technician/maintenance/update/${maintenanceId}`, maintenance);
  }
 
  // Optional: Get maintenance by ID (if needed later)
  getMaintenanceById(maintenanceId: number): Observable<any> {
    return this.http.get<any>(`${this.serverName}/api/technician/maintenance/${maintenanceId}`);
  }
  getAllHospitals(): Observable<any[]> {
    return this.http.get<any[]>(`${this.serverName}/api/hospitals`);
  }
 
  // Get equipment by hospital ID
  getEquipmentByHospital(hospitalId: number): Observable<any[]> {
    return this.http.get<any[]>(`${this.serverName}/api/equipment/hospital/${hospitalId}`);
  }
 
  // Schedule maintenance
  scheduleMaintenance(data: any): Observable<any> {
    return this.http.post<any>(`${this.serverName}/api/technician/maintenance`, data);
  }
 
 
 
  getorders():Observable<any>{
    return this.http.get<any>(`${this.serverName}/orders`);
  }
 
  UpdateOrderStatus(orderId:number,newStatus:string):Observable<any>{
    return this.http.put<any>(`${this.serverName}/order/update/${orderId}`,{status:newStatus});
  }
 
}
 