
package es.deusto.sd.google.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import es.deusto.sd.strava.dto;
import es.deusto.sd.google.auth.service.GoogleAuthService;

@RestController
@RequestMapping("/google")
public class GoogleAuthController {

    private final GoogleAuthService authService;

    public GoogleAuthController(GoogleAuthService authService) {
        this.authService = authService;
    }

    /**
     * Login a user with Google credentials.
     *
     * @param loginDTO containing email and password
     * @return token if successful
     */
    @PostMapping("/login")
    public ResponseEntity<String> loginWithGoogle(@RequestBody LoginDTO loginDTO) {
        try {
            String token = authService.login(loginDTO.getEmail(), loginDTO.getPassword());
            if (token != null) {
                return ResponseEntity.ok(token);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials.");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                 .body("Error during login: " + e.getMessage());
        }
    }

    /**
     * Validate Google credentials.
     *
     * @param email the user's email
     * @param password the user's password
     * @return true if valid, false otherwise
     */
    @GetMapping("/validate/google")
    public ResponseEntity<Boolean> validateEmailGoogle(
            @RequestParam("email") String email,
            @RequestParam("pass") String password) {
        try {
            boolean isValid = authService.validate(email, password);
            return ResponseEntity.ok(isValid);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                 .body(false);
        }
    }
}
