package com.hominhnhut.WMN_BackEnd.restController;

import com.hominhnhut.WMN_BackEnd.domain.request.ChangePasswordRequest;
import com.hominhnhut.WMN_BackEnd.domain.request.UserDtoRequest;
import com.hominhnhut.WMN_BackEnd.domain.response.UserDtoResponse;
import com.hominhnhut.WMN_BackEnd.service.Interface.PageService;
import com.hominhnhut.WMN_BackEnd.service.Interface.UserService;
import com.hominhnhut.WMN_BackEnd.service.impl.PageServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@CrossOrigin(origins = "http://localhost:5173/")
@RestController
@RequestMapping("/user")
@Slf4j
@FieldDefaults(makeFinal = true, level = AccessLevel.PRIVATE)
public class UserController {

   UserService userService;
   PageService pageService;

    public UserController(UserService userService, PageServiceImpl pageService) {
        this.userService = userService;
        this.pageService = pageService;
    }

    @GetMapping("/")
    public ResponseEntity<
         List<UserDtoResponse>> getAllUser() {
        log.info("hello");
        List<UserDtoResponse> userDtoResponses = this.userService.getAll();
        return ResponseEntity.ok(userDtoResponses);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDtoResponse> getByIdUser(
            @PathVariable String id
    ) {
        UserDtoResponse userDtoResponse = this.userService.findById(id);
        return ResponseEntity.ok(userDtoResponse);
    }

    @GetMapping("/role/{id}")
    public ResponseEntity<
                    Set<UserDtoResponse>> getAllUserByRoleId(
                            @PathVariable("id") Integer roleName
    ) {

        Set<UserDtoResponse> userDtoResponses = this.userService.getUserByRoleId(roleName);
        return ResponseEntity.ok(userDtoResponses);
    }

    @GetMapping("/myinfo")
    public ResponseEntity<UserDtoResponse> getMyInfo() {
        UserDtoResponse response = userService.getMyInfo();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/changeMyPass")
    public ResponseEntity<UserDtoResponse> changeMyPass(
            @AuthenticationPrincipal Jwt jwt, @RequestBody ChangePasswordRequest changePasswordRequest
            ) {
        UserDtoResponse response = userService.changeMyPassword(jwt.getClaimAsString("sub"),
                changePasswordRequest.getPwOld(), changePasswordRequest.getPwNew());
                return ResponseEntity.ok(response);
    }

    @PostMapping("/")
    public ResponseEntity<UserDtoResponse> saveUser(
          @Valid @RequestBody UserDtoRequest request
            ) {
        UserDtoResponse userDtoResponse = this.userService.save(request);
        return ResponseEntity.ok(userDtoResponse);
    }


    @PutMapping("/{id}")
    public ResponseEntity<UserDtoResponse> updateUser(
            @PathVariable("id") String idUpdate,
            @Valid @RequestBody UserDtoRequest request
    ) {
        UserDtoResponse userDtoResponse = this.userService.update(idUpdate,request);
        return ResponseEntity.ok(userDtoResponse);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable(value = "id") String idDelete
    ) {
        this.userService.delete(idDelete);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/username/{usernameContain}")
    public ResponseEntity<
                    Set<UserDtoResponse>> getAllUserByUsernameContain(
            @PathVariable("usernameContain") String usernameContain
    ) {
        System.out.println(usernameContain);
        Set<UserDtoResponse> userDtoResponses = this.userService.getUserByUsernameContaining(usernameContain);
        return ResponseEntity.ok(userDtoResponses);
    }

    @GetMapping("/page/")
    public ResponseEntity<
                    Page<UserDtoResponse>> getUserPage(
                           @RequestParam("roleId") Integer roleId,
                           @RequestParam("pageNumber") Integer pageNumber,
                           @RequestParam("pageSize") Integer pageSize
    ) {
        System.out.println("page");
        Page<UserDtoResponse> listUserDto =
                this.pageService.getPageUserByRoleId(pageNumber,pageSize,roleId);
        return ResponseEntity.ok(listUserDto);
    }

    @GetMapping("/google")
    public ResponseEntity<
            Set<UserDtoResponse>> getUserGoogle() {
        Set<UserDtoResponse> responses = userService.findUsersByGoogleIdNotNull();
        return ResponseEntity.ok(responses);
    }






}
