package com.wecp.medicalequipmentandtrackingsystem.service;
 
 
import java.util.ArrayList;
import java.util.List;
 
import com.wecp.medicalequipmentandtrackingsystem.dto.EquipmentDTO;
import com.wecp.medicalequipmentandtrackingsystem.dto.HospitalDTO;
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
 
    // Return List of HospitalDTOs
    public List<HospitalDTO> getAllHospitals() throws Exception {
        List<Hospital> hospitals = hospitalRepository.findAll();
        List<HospitalDTO> hospitalDTOs = new ArrayList<>();
 
        for (Hospital hospital : hospitals) {
            hospitalDTOs.add(convertToDTO(hospital));
        }
 
        return hospitalDTOs;
    }
 
    // Accept HospitalDTO and return HospitalDTO
    public HospitalDTO addHospital(HospitalDTO hospitalDTO) throws Exception {
        Hospital existingHospital = hospitalRepository.findByNameAndLocation(hospitalDTO.getName(), hospitalDTO.getLocation());
        if (existingHospital != null ) {
            throw new RuntimeException("Hospital already exists.");
        }
        // if(existingHospital.getLocation()==hospitalDTO.getLocation()|| existingHospital.getName()==hospitalDTO.getName()){
        //     throw new RuntimeException("Hospital already exists.");
        // }
 
        Hospital hospital = convertToEntity(hospitalDTO);
 
        if (!hospital.getEquipmentList().isEmpty()) {
            for (Equipment equipment : hospital.getEquipmentList()) {
                equipment.setHospital(hospital);
            }
        }
 
        Hospital savedHospital = hospitalRepository.save(hospital);
        return convertToDTO(savedHospital);
    }
 
    //  Helper: Convert Entity to DTO
    private HospitalDTO convertToDTO(Hospital hospital) {
        HospitalDTO dto = new HospitalDTO();
        dto.setId(hospital.getId());
        dto.setName(hospital.getName());
        dto.setLocation(hospital.getLocation());
 
        // Optional: Map equipment IDs
        List<Long> equipmentIds = new ArrayList<>();
        for (Equipment equipment : hospital.getEquipmentList()) {
            equipmentIds.add(equipment.getId());
        }
        dto.setEquipmentIds(equipmentIds);
 
        return dto;
    }
 
    //  Helper: Convert DTO to Entity
    private Hospital convertToEntity(HospitalDTO dto) {
        Hospital hospital = new Hospital();
        hospital.setName(dto.getName());
        hospital.setLocation(dto.getLocation());
 
        // Optional: You can fetch Equipment by IDs if needed
        hospital.setEquipmentList(new ArrayList<>()); // Empty for now
 
        return hospital;
    }
 
    public Hospital getHospitalById(Long id) throws Exception {
        return hospitalRepository.findById(id).get();
    }
 
    public Equipment addEquipment(Long id, Equipment equipment) {
        Hospital hsptl = hospitalRepository.findById(id)
            .orElseThrow(() -> new RuntimeException("Hospital not found"));
 
        equipment.setHospital(hsptl);
        return equipmentRepository.save(equipment);
    }
 
    public List<Equipment> getAllEquipmentsById(Long hospitalId) {
        return hospitalRepository.findById(hospitalId).get().getEquipmentList();
    }
 
    public List<Equipment> getAllEquipmentsByName(String name) {
        return hospitalRepository.findByName(name).getEquipmentList();
    }
}
 
 
 
 
 
 
 
 
 
 
