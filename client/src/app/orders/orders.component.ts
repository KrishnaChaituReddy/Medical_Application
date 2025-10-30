import { Component, OnInit } from '@angular/core';
import { AbstractControl, FormBuilder, FormGroup, ValidationErrors, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { HttpService } from '../../services/http.service';
import { AuthService } from '../../services/auth.service';
@Component({
  selector: 'app-orders',
  templateUrl: './orders.component.html',
  styleUrls: ['./orders.component.scss']
})
export class OrdersComponent implements OnInit {
  showError: boolean = false;
  errorMessage: any;
  showMessage: any;
  responseMessage: any;
  orderList: any[] = [];
  statusModel: any = { newStatus: null };
  status: any = '';
  statusList: string[] = [];
  showModal: boolean = false;
  constructor(private orderService: HttpService, private router: Router) {}
  ngOnInit(): void {
    this.getOrders();
  }
  getOrders(): void {
    this.orderService.getorders().subscribe({
      next: (response) => {
        this.orderList = response;
        // const orderStatuses = this.orderList.map(order => order.status);
        // const equipmentStatuses = this.orderList.map(order => order.equipment?.status);
        // this.statusList = Array.from(new Set([...orderStatuses, ...equipmentStatuses]));
        //this.statusList = Array.from(new Set(this.orderList.map(order => order.status)));
        this.showError = false;
      },
      error: (error) => {
        this.showError = true;
        this.errorMessage = 'Failed to load orders.';
        console.error(error);
      }
    });
  }
  viewDetails(orderId: number): void {
    this.router.navigate(['/orders', orderId]);
  }
  edit(order: any): void {
    this.showModal = true;
    this.statusModel = { orderId: order.id, newStatus: order.status };
  }
  closeModal(): void {
    this.showModal = false;
    this.statusModel = { newStatus: null };
  }
  update(orderId: number,statusClicked:string): void {
    if (!this.statusModel.newStatus || this.statusModel.newStatus.trim() === '') {
      this.showError = true;
      this.errorMessage = 'Please select a status.';
      return;
    }
    this.orderService.UpdateOrderStatus(orderId,statusClicked).subscribe({
      next: (response) => {
        this.responseMessage = 'Status updated.';
        this.showMessage = true;
        this.showError = false;
        this.getOrders();
        this.closeModal();
      },
      error: (error) => {
        this.showError = true;
        this.errorMessage = 'Failed to update order status.';
        console.error(error);
      }
    });
  }
}
