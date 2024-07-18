package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.domain.request.RoleDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.RoleDtoResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.RoleService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@CrossOrigin(origins = "http://localhost:5173/")
@RestController
@RequestMapping("/role")
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class RoleController {

    RoleService roleService;

    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }


    @GetMapping
    public ResponseEntity<
                    List<RoleDtoResponse>> getAllRole() {

        List<RoleDtoResponse> roleDtoResponses = this.roleService.findAll();
        return ResponseEntity.ok(roleDtoResponses);
    }

    @GetMapping("/{id}")
    public ResponseEntity<RoleDtoResponse> getByRoleId(
            @PathVariable Integer id
    ) {
        RoleDtoResponse roleDtoResponse = this.roleService.findById(id);
        return ResponseEntity.ok(roleDtoResponse);
    }

    @PostMapping("/")
    public ResponseEntity<RoleDtoResponse> saveRole(
          @Valid @RequestBody RoleDtoRequest request
    ) {
        RoleDtoResponse roleDtoResponse = this.roleService.save(request);
        return ResponseEntity.ok(roleDtoResponse);
    }

    @PutMapping("/{id}")
    public ResponseEntity<RoleDtoResponse> updateRole(
            @PathVariable("id") Integer idUpdate,
            @Valid @RequestBody RoleDtoRequest request
    ) {
        RoleDtoResponse roleDtoResponse = this.roleService.update(idUpdate,request);
        return ResponseEntity.ok(roleDtoResponse);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRole(
            @PathVariable("id") Integer idDelete
    ) {
        this.roleService.delete(idDelete);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/overview")
    public ResponseEntity<
            Set<RoleDtoResponse>> getRoleOverviewResponse(

    ) {
        Set<RoleDtoResponse> responses = this.roleService.getRoleOverview();
        return ResponseEntity.ok(responses);
    }


}
