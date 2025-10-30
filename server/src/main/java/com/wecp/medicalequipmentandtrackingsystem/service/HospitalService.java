package com.wecp.medicalequipmentandtrackingsystem.service;


import java.util.ArrayList;
import java.util.List;

import com.wecp.medicalequipmentandtrackingsystem.entitiy.Equipment;
import com.wecp.medicalequipmentandtrackingsystem.entitiy.Hospital;
import com.wecp.medicalequipmentandtrackingsystem.repository.EquipmentRepository;
import com.wecp.medicalequipmentandtrackingsystem.repository.HospitalRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class HospitalService {
    @Autowired
    private HospitalRepository hospitalRepository;

    @Autowired
    private EquipmentRepository equipmentRepository;

    public List<Hospital> getAllHospitals() throws Exception{
        return hospitalRepository.findAll();
    }

    public Hospital addHospital(Hospital hospital) throws Exception {
        Hospital existingHospital = hospitalRepository.findByNameAndLocation(hospital.getName(), hospital.getLocation());
        if (existingHospital != null) {
            throw new RuntimeException("Hospital already with same name and location");
        }
    
        if (!hospital.getEquipmentList().isEmpty()) {
            for (Equipment equipment : hospital.getEquipmentList()) {
                equipment.setHospital(hospital); // Set the hospital reference
            }
        }
    
        return hospitalRepository.save(hospital); // Save hospital and cascade to equipment
    }

    public Hospital getHospitalById(Long id) throws Exception{
        return hospitalRepository.findById(id).get();
    }

    public Equipment addEquipment(Long id, Equipment equipment) {
        Hospital hsptl = hospitalRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("Hospital not found"));
    
        equipment.setHospital(hsptl); // Set the relationship
        return equipmentRepository.save(equipment); // Save only the equipment
    }
    public List<Equipment> getAllEquipmentsById(Long hospitalId){
 
        return hospitalRepository.findById(hospitalId).get().getEquipmentList();
 
    }
    
    
}