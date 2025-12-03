package org.example.expert.domain.user.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UserChangePasswordRequest {

    @NotBlank
    private String oldPassword;
    @NotBlank @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[A-Z]).{8,}$",
            // ^시작(?= 긍정 전방 탐색 .* 0개 이상 [0-9 문자열])(?= 긍정 전방 탐색.* 0개이상 [A-Z 범위]).{8자이상 최대는 미정} $끝
            message = "새 비밀번호는 8자 이상이어야 하고, 숫자와 대문자를 포함해야 합니다."
    )
    private String newPassword;
}
