import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { HttpService } from '../../services/http.service';

@Component({
  selector: 'app-schedule-maintenance',
  templateUrl: './schedule-maintenance.component.html',
  styleUrls: ['./schedule-maintenance.component.scss']
})

export class ScheduleMaintenanceComponent implements OnInit {

  itemForm !: FormGroup;
  formModel: any = { status: null };
  showError: boolean = false;
  errorMessage: any;
  hospitalList: any[] = [];
  assignModel: any = {};
  showMessage: any;
  responseMessage: any;
  equipmentList: any[] = [];
  today : string = new Date().toISOString().split('T')[0];

  constructor(private fb: FormBuilder, private httpService: HttpService) {
    this.itemForm = this.fb.group({
      hospitalId: ['', Validators.required],
      equipmentId: ['', Validators.required],
      scheduledDate: ['', [Validators.required]],
      completedDate: [{value : '' , disabled : true}],
      description: ['', Validators.required],
      status: ['', Validators.required]
    });
  }

  ngOnInit(): void {
    this.getHospital();
  }

  dateValidator(control: any): { [key: string]: boolean } | null {
    const today = new Date().toISOString().split('T')[0];
    if (control.value && control.value < today) {
      return { invalidDate: true };
    }
    return null;
  }
  
  getHospital(): void {
    this.httpService.getAllHospitals().subscribe({
      next: (data) => this.hospitalList = data,
      error: () => {
        this.showError = true;
        this.errorMessage = 'Failed to load hospitals';
      }
    });
  }

  onHospitalSelect(): void {
    const hospitalId = this.itemForm.get('hospitalId')?.value;
    if (hospitalId) {
      this.httpService.getEquipmentByHospital(hospitalId).subscribe({
        next: (data) => this.equipmentList = data,
        error: () => {
          this.showError = true;
          this.errorMessage = 'Failed to load equipment';
        }
      });
    }
  }

  onSubmit(): void {
    if (this.itemForm.valid) {
      this.httpService.scheduleMaintenance(this.itemForm.get('equipmentId')?.value , this.itemForm.value).subscribe({
        next: () => {
          this.responseMessage = 'Save Successfully';
          this.showMessage = true;
          this.itemForm.reset();

          setTimeout(()=>{
          this.showMessage = false;
          } , 1500);
        },
        error: () => {
          this.errorMessage = 'Failed to schedule maintenance';
          this.showError = true;

          setTimeout(()=>{
            this.errorMessage = false;
            } , 1500);
        }
      });
    }
  }
}

