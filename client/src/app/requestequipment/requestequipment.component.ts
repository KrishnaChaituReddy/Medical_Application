import { Component, OnInit } from '@angular/core';
import { ReactiveFormsModule } from '@angular/forms';
import { AbstractControl, FormBuilder, FormGroup, ValidationErrors, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { HttpService } from '../../services/http.service';
import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-requestequipment',
  templateUrl: './requestequipment.component.html',
  styleUrls: ['./requestequipment.component.scss']
})
export class RequestequipmentComponent implements OnInit {
  equipmentForm!: FormGroup;
  hospitals: string[] = ['AIIMS', 'Apollo Hospital'];
  equipments: string[] = ["bed", "laptop"];
  statuses: string[] = ['Initiated'];

  constructor(private fb: FormBuilder, private httpService: HttpService) {}

  ngOnInit(): void {
    this.equipmentForm = this.fb.group({
      hospital: ['', Validators.required],
      quantity: [null, [Validators.required, Validators.min(1)]],
      equipment: ['', Validators.required],
      status: ['', Validators.required],
      orderDate: ['', Validators.required]
    });

    this.loadhospitals();
  }

  onSubmit(): void {
    if (this.equipmentForm.valid) {
      console.log('Form Data:', this.equipmentForm.value);
      alert('Equipment request submitted successfully!');
    } else {
      alert('Please fill all required fields.');
    }
  }

  loadhospitals(){
    this.httpService.getAllHospitals().subscribe({
      next:(response)=>{
        this.hospitals=response;
      },
      error:(err)=> console.log("Error loading Hospital details", err)
    });
  }

  loadEquipments(){
  
  }
}


{}