import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { HttpService } from '../../services/http.service';

@Component({
  selector: 'app-createhospital',
  templateUrl: './createhospital.component.html',
  styleUrls: ['./createhospital.component.scss']
})
export class CreatehospitalComponent implements OnInit {
  itemForm!: FormGroup;
  equipmentForm!: FormGroup;
  hospitalList: any[] = [];
  assignModel: any = {};
  showEquipmentForm: boolean = false;
  showError: boolean = false;
  errorMessage: string = '';
  responseMessage: string = '';
  showMessage: string = '';

  // Search and Sort
  searchQuery: string = '';
  sortField: string = '';
  sortDirection: 'asc' | 'desc' = 'asc';

  currentPage: number = 1;
  itemsPerPage: number = 5;

  constructor(
    private itemFb: FormBuilder,
    private router: Router,
    private equimentForm: FormBuilder,
    private httpService: HttpService
  ) {}

  ngOnInit(): void {
    this.itemForm = this.itemFb.group({
      name: ['', [Validators.required, Validators.pattern(/^[A-Za-z\s]+$/), Validators.minLength(3)]],
      location: ['', [Validators.required, Validators.minLength(3)]]
    });

    this.getHospital();
  }

  onSubmit() {
    if (this.itemForm.valid) {
      this.httpService.createHospital(this.itemForm.value).subscribe({
        next: () => {
          this.responseMessage = "Hospital created Successfully";
          setTimeout(() => {
            this.itemForm.reset();
            this.responseMessage = "";
          }, 1500);
          this.getHospital();
        },
        error: () => {
          this.showError = true;
          this.errorMessage = 'Hospital Already Exists';
          setTimeout(() => {
            this.itemForm.reset();
            this.errorMessage = "";
            this.responseMessage = "";
            this.showError = false;
          }, 1500);
        }
      });
    }
  }

  getHospital() {
    this.httpService.getHospital().subscribe({
      next: (data) => {
        this.hospitalList = data;
      },
      error: () => {
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
      hospitalId: [hospital.id, Validators.required]
    });

    this.assignModel = hospital;
  }

  closeModal() {
    this.showEquipmentForm = false;
    this.equipmentForm.reset();
  }

  submitEquipment() {
    if (this.equipmentForm.valid) {
      this.httpService.addEquipment(this.equipmentForm.value, this.equipmentForm.get('hospitalId')).subscribe({
        next: () => {
          this.showMessage = 'Equipment assigned successfully!';
          setTimeout(() => {
            this.showEquipmentForm = false;
            this.showMessage = '';
          }, 1500);
        },
        error: () => {
          this.showError = true;
          this.errorMessage = 'Error assigning equipment.';
          setTimeout(() => {
            this.showEquipmentForm = false;
            this.showError = false;
          }, 1500);
        }
      });
    }
  }

  sortBy(field: string) {
    if (this.sortField === field) {
      this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortField = field;
      this.sortDirection = 'asc';
    }

    this.hospitalList.sort((a, b) => {
      const valueA = a[field].toLowerCase();
      const valueB = b[field].toLowerCase();

      if (valueA < valueB) return this.sortDirection === 'asc' ? -1 : 1;
      if (valueA > valueB) return this.sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }

  get filteredHospitals() {
    if (!this.searchQuery) return this.hospitalList;
    const query = this.searchQuery.toLowerCase();
    return this.hospitalList.filter(hospital =>
      hospital.name.toLowerCase().includes(query) ||
      hospital.location.toLowerCase().includes(query)
    );
  }

  get paginatedHospitals() {
    const startIndex = (this.currentPage - 1) * this.itemsPerPage;
    const endIndex = startIndex + this.itemsPerPage;
    return this.filteredHospitals.slice(startIndex, endIndex);
  }

  get totalPages(): number {
    return Math.ceil(this.filteredHospitals.length / this.itemsPerPage);
  }

  changePage(page: number) {
    if (page >= 1 && page <= this.totalPages) {
      this.currentPage = page;
    }
  }
}