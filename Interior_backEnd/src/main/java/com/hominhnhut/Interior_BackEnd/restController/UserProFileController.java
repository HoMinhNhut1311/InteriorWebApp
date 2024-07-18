package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.domain.request.UserProfileDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.UserProfileService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "http://localhost:5173/")
@RestController
@RequestMapping("/profile")
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class UserProFileController {

   UserProfileService userProfileService;

    public UserProFileController(UserProfileService userProfileService) {
        this.userProfileService = userProfileService;
    }

    @GetMapping("/")
    public ResponseEntity<
                    List<UserDtoResponse>> getAllUser() {

        List<UserDtoResponse> userDtoResponses = this.userProfileService.findAll();
        return ResponseEntity.ok(userDtoResponses);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDtoResponse> getByIdUser(
            @PathVariable String id
    ) {
        UserDtoResponse userDtoResponse = this.userProfileService.getById(id);
        return ResponseEntity.ok(userDtoResponse);
    }

    @PostMapping("/")
    public ResponseEntity<UserDtoResponse> saveUser(
          @Valid @RequestBody UserProfileDtoRequest request
            ) {
        UserDtoResponse userDtoResponse = this.userProfileService.save(request);
        return ResponseEntity.ok(userDtoResponse);
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserDtoResponse> updateUser(
            @PathVariable("id") String idUpdate,
            @Valid @RequestBody UserProfileDtoRequest request
    ) {
        UserDtoResponse userDtoResponse =
                this.userProfileService.update(idUpdate,request);
        return ResponseEntity.ok(userDtoResponse);
    }



    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable("id") String idDelete
    ) {
        this.userProfileService.delete(idDelete);
        return ResponseEntity.noContent().build();
    }



}
