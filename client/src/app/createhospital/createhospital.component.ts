import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../../services/auth.service';
import { HttpService } from '../../services/http.service';
@Component({
  selector: 'app-createhospital',
  templateUrl: './createhospital.component.html',
  styleUrls: ['./createhospital.component.scss']
})
export class CreatehospitalComponent implements OnInit {
  itemForm!: FormGroup;
  equipmentForm!: FormGroup;
  formModel: any = { status: null };
  showError: boolean = false;
  errorMessage: any;
  hospitalList: any[] = [];
  assignModel: any = {};
  showMessage: any;
  responseMessage: any;
  showEquipmentForm: boolean = false;
  constructor(
    private itemFb: FormBuilder,
    private router: Router,
    private equimentForm: FormBuilder,
    private httpService: HttpService
  ) {}
  ngOnInit(): void {
    this.itemForm = this.itemFb.group({
      name: ['', [Validators.required, Validators.pattern(/^[A-Za-z\s]+$/)]],
      location: ['', [Validators.required]]
    });
 
    this.getHospital();
  }
 
  onSubmit() {
    if (this.itemForm.valid) {
      this.httpService.createHospital(this.itemForm.value).subscribe({
        next: (response) => {
          this.responseMessage = "Hospital created Successfully";
          setTimeout(()=>
          {
            this.itemForm.reset();
            this.responseMessage="";
          },3000);
          this.getHospital();
        },
        error: (err) => {
          this.showError = true;
          this.errorMessage = 'Error creating hospital';
          setTimeout(()=>
            {
              this.itemForm.reset();
              this.errorMessage="";
              this.responseMessage="";
              this.showError = false;
            },3000);
        }
      });
    }
  }
  getHospital() {
    this.httpService.getHospital().subscribe({
      next: (data) => {
        this.hospitalList = data;
      },
      error: (err) => {
        this.showError = true;
        this.errorMessage = "Failed to load Hospitals.";
      }
    });
  }

  addEquipment(hospital: any) {
    this.showEquipmentForm = true;
    this.equipmentForm = this.equimentForm.group({
      name: ['', [Validators.required, Validators.minLength(2)]],
      description: ['', [Validators.required, Validators.minLength(2)]],
      hospitalId: ['', Validators.required]
    });
 
    this.assignModel = hospital;
 
    this.equipmentForm.patchValue({
      hospitalId: hospital.id
    });
  }
 
  closeModal() {
    this.showEquipmentForm = false;
    this.equipmentForm.reset();
  }
 
  submitEquipment() {
    if (this.equipmentForm.valid) {
      this.httpService.addEquipment(this.equipmentForm.value, this.equipmentForm.get('hospitalId')).subscribe({
        next: (res) => {
          this.showMessage = 'Equipment assigned successfully!';
          setTimeout(() => {
            this.showEquipmentForm = false;
            this.showMessage = null;
          }, 3000);
        },
        error: (err) => {
          this.showError = true;
          this.errorMessage = 'Error assigning equipment.';
          setTimeout(() => {
            this.showEquipmentForm = false;
            this.showError =false;
          }, 3000);
        }
      });
    }
  }
}
 
 